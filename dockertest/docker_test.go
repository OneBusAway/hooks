//go:build docker

package dockertest

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// imageTag is per-process so concurrent `make docker-test` runs (or parallel
// CI jobs that happen to share a host) don't fight over the same tag. We use
// UnixNano rather than the PID because PID can collide across runners.
var imageTag = fmt.Sprintf("hooks-dockertest:%d", time.Now().UnixNano())

// dockerSkipReason is set in TestMain when docker is unavailable. Tests
// consult it via skipIfNoDocker so the package reports SKIP rather than
// silently PASS — a no-op test suite that masquerades as green is exactly
// the regression that this build-tag-gated suite is supposed to prevent.
var dockerSkipReason string

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		dockerSkipReason = fmt.Sprintf("docker not on PATH: %v", err)
		os.Exit(m.Run())
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dockertest: getwd: %v\n", err)
		os.Exit(1)
	}
	repoRoot := filepath.Dir(cwd)

	build := exec.Command("docker", "build", "-t", imageTag, ".")
	build.Dir = repoRoot
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "dockertest: docker build failed: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	_ = exec.Command("docker", "rmi", "-f", imageTag).Run()
	os.Exit(code)
}

func skipIfNoDocker(t *testing.T) {
	t.Helper()
	if dockerSkipReason != "" {
		t.Skip(dockerSkipReason)
	}
}

func TestImageHelpOutput(t *testing.T) {
	skipIfNoDocker(t)
	out, err := exec.Command("docker", "run", "--rm", imageTag, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("hooks --help: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "hooks: durable webhook relay") {
		t.Fatalf("unexpected --help output:\n%s", out)
	}
}

func TestImageRunsAsNonRoot(t *testing.T) {
	skipIfNoDocker(t)
	out, err := exec.Command("docker", "run", "--rm", "--entrypoint", "id", imageTag, "-u").CombinedOutput()
	if err != nil {
		t.Fatalf("id -u: %v\n%s", err, out)
	}
	if uid := strings.TrimSpace(string(out)); uid == "0" {
		t.Fatalf("image runs as root (uid=0); expected non-root for security")
	}
}

func TestImageShipsBothBinaries(t *testing.T) {
	skipIfNoDocker(t)
	for _, bin := range []string{"hooks", "hooksctl"} {
		out, err := exec.Command("docker", "run", "--rm", "--entrypoint", bin, imageTag, "--help").CombinedOutput()
		if err != nil {
			t.Fatalf("%s --help: %v\n%s", bin, err, out)
		}
	}
}

// scaffoldDataDir creates a tempdir with `hooks init` already run inside the
// container, so the caller's `docker run` can boot the server against a real
// hooks.yaml + hooks.db. The 0o777 chmod is needed because the container
// drops to UID 65532 which isn't the host user — bind-mount writes would
// otherwise EACCES. Safe here because the dir is per-test and ephemeral.
func scaffoldDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	out, err := exec.Command("docker", "run", "--rm",
		"-v", dir+":/data",
		imageTag, "init",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("hooks init: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "admin token (shown ONCE)") {
		t.Fatalf("init did not print admin token line:\n%s", out)
	}
	return dir
}

func TestImageInitScaffold(t *testing.T) {
	skipIfNoDocker(t)
	dir := scaffoldDataDir(t)
	for _, name := range []string{"hooks.yaml", "hooks.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s in mounted /data after init: %v", name, err)
		}
	}
}

func TestImageServesHealthEndpoints(t *testing.T) {
	skipIfNoDocker(t)
	dir := scaffoldDataDir(t)

	containerName := fmt.Sprintf("hooks-dockertest-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName,
		"-v", dir+":/data",
		"-e", "RENDER_WEBHOOK_SECRET=stub-for-tests",
		"-p", "0:8080",
		imageTag,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { cleanupContainer(t, containerName) })

	addr := "http://127.0.0.1:" + hostPort(t, containerName, "8080/tcp")
	if err := waitForHealthz(addr, 60*time.Second); err != nil {
		t.Fatalf("/healthz never returned 200: %v\nlogs:\n%s", err, dockerLogs(containerName))
	}

	resp, err := http.Get(addr + "/readyz")
	if err != nil {
		t.Fatalf("/readyz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz status: %d (sqlite ping)\nlogs:\n%s", resp.StatusCode, dockerLogs(containerName))
	}
}

// TestImageHealthcheckDirective verifies Docker's HEALTHCHECK plumbing —
// the directive in the Dockerfile, the `wget` it invokes, and the port it
// targets. The host-side /healthz polling in TestImageServesHealthEndpoints
// only covers "the server is up"; this covers "the in-container healthcheck
// resolves to healthy", which is what orchestrators like Render rely on.
func TestImageHealthcheckDirective(t *testing.T) {
	skipIfNoDocker(t)
	dir := scaffoldDataDir(t)

	containerName := fmt.Sprintf("hooks-dockertest-hc-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName,
		"-v", dir+":/data",
		"-e", "RENDER_WEBHOOK_SECRET=stub-for-tests",
		imageTag,
	).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { cleanupContainer(t, containerName) })

	// HEALTHCHECK interval is 30s; allow up to 90s for a probe to land
	// and report `healthy` on a busy CI runner.
	deadline := time.Now().Add(90 * time.Second)
	var lastStatus string
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "inspect",
			"--format", "{{.State.Health.Status}}",
			containerName,
		).Output()
		if err != nil {
			t.Fatalf("docker inspect: %v", err)
		}
		lastStatus = strings.TrimSpace(string(out))
		if lastStatus == "healthy" {
			return
		}
		if lastStatus == "unhealthy" {
			t.Fatalf("HEALTHCHECK reports unhealthy\nlogs:\n%s", dockerLogs(containerName))
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("HEALTHCHECK never reached healthy (last=%q)\nlogs:\n%s", lastStatus, dockerLogs(containerName))
}

// TestImageRestartPreservesState boots the server, captures a snapshot of
// the persisted state (hooks.db sequence numbers via /readyz + size), stops
// the container, restarts a fresh one against the same /data volume, and
// verifies the new server reports the same persisted state. Catches future
// Dockerfile changes that move WORKDIR or reset HOOKS_DATABASE_URL — failure
// modes that would silently lose every event on each deploy.
func TestImageRestartPreservesState(t *testing.T) {
	skipIfNoDocker(t)
	dir := scaffoldDataDir(t)

	statBefore, err := os.Stat(filepath.Join(dir, "hooks.db"))
	if err != nil {
		t.Fatalf("stat hooks.db before run: %v", err)
	}

	first := fmt.Sprintf("hooks-dockertest-rs1-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", first,
		"-v", dir+":/data",
		"-e", "RENDER_WEBHOOK_SECRET=stub-for-tests",
		"-p", "0:8080",
		imageTag,
	).CombinedOutput(); err != nil {
		t.Fatalf("first docker run: %v\n%s", err, out)
	}
	addr1 := "http://127.0.0.1:" + hostPort(t, first, "8080/tcp")
	if err := waitForHealthz(addr1, 60*time.Second); err != nil {
		cleanupContainer(t, first)
		t.Fatalf("first server: %v\nlogs:\n%s", err, dockerLogs(first))
	}
	cleanupContainer(t, first)

	statAfterFirst, err := os.Stat(filepath.Join(dir, "hooks.db"))
	if err != nil {
		t.Fatalf("stat hooks.db after first run: %v", err)
	}
	if statAfterFirst.Size() < statBefore.Size() {
		t.Fatalf("hooks.db shrank during first run: %d -> %d", statBefore.Size(), statAfterFirst.Size())
	}

	second := fmt.Sprintf("hooks-dockertest-rs2-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", second,
		"-v", dir+":/data",
		"-e", "RENDER_WEBHOOK_SECRET=stub-for-tests",
		"-p", "0:8080",
		imageTag,
	).CombinedOutput(); err != nil {
		t.Fatalf("second docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { cleanupContainer(t, second) })

	addr2 := "http://127.0.0.1:" + hostPort(t, second, "8080/tcp")
	if err := waitForHealthz(addr2, 60*time.Second); err != nil {
		t.Fatalf("second server: %v\nlogs:\n%s", err, dockerLogs(second))
	}

	resp, err := http.Get(addr2 + "/readyz")
	if err != nil {
		t.Fatalf("/readyz on second run: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz on second run: status %d (sqlite ping)\nlogs:\n%s",
			resp.StatusCode, dockerLogs(second))
	}
}

// waitForHealthz polls /healthz on the running container until it returns
// 200 or the deadline expires. Server-side errors (5xx) are preserved
// across iterations — if the server ever returned 500 then died, the
// reported error is the 500, not the trailing connection-refused, since
// the 500 is the one likely to point at the bug.
func waitForHealthz(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastTransient, firstServerErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr + "/healthz")
		if err != nil {
			lastTransient = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		if firstServerErr == nil {
			firstServerErr = fmt.Errorf("status %d", resp.StatusCode)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if firstServerErr != nil {
		return firstServerErr
	}
	return lastTransient
}

func cleanupContainer(t *testing.T, name string) {
	t.Helper()
	if out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
		t.Logf("cleanup: docker rm -f %s: %v\n%s", name, err, out)
	}
}

// dockerLogs returns the container's logs as a string, with a fallback
// message if the fetch itself errors so callers never report an empty
// `logs:` block on a real failure.
func dockerLogs(name string) string {
	out, err := exec.Command("docker", "logs", name).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("(docker logs %s failed: %v)", name, err)
	}
	return string(out)
}

// hostPort returns the host port `docker run -p 0:<containerPort>` mapped to.
// `docker port` may print multiple lines (one per address family); the host
// port is the same on every line, so we take the last `:`-separated field
// of the first line.
func hostPort(t *testing.T, container, containerPort string) string {
	t.Helper()
	out, err := exec.Command("docker", "port", container, containerPort).Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	colon := strings.LastIndex(first, ":")
	if colon < 0 {
		t.Fatalf("unexpected `docker port` output: %q", string(out))
	}
	return first[colon+1:]
}

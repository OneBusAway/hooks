//go:build docker

package dockertest

import (
	"bytes"
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
	if strings.TrimSpace(string(out)) == "0" {
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
//
// `hooks init` prints a one-time admin token and a bootstrap signup code on
// stdout. Both are credentials, so we never put the raw output in t.Fatalf
// messages — CI logs are public on PRs.
func scaffoldDataDir(t *testing.T) string {
	t.Helper()
	dir, _ := scaffoldDataDirCapturingToken(t)
	return dir
}

// scaffoldDataDirCapturingToken is scaffoldDataDir plus the one-time admin
// token. Caller MUST treat the returned token as a secret — never put it
// into t.Logf / t.Fatalf or any output that lands in CI logs. The redact
// helper exists precisely so this is easy to do.
func scaffoldDataDirCapturingToken(t *testing.T) (string, string) {
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
		t.Fatalf("hooks init: %v (output redacted: contains one-time admin token)", err)
	}
	token := extractAdminToken(out)
	if token == "" {
		t.Fatal("init did not print an admin-token line (output redacted)")
	}
	return dir, token
}

func extractAdminToken(out []byte) string {
	const marker = "admin token (shown ONCE):"
	for _, line := range strings.Split(string(out), "\n") {
		// HasPrefix on the trimmed line — substring matching would silently
		// return any text that follows the token if `hooks init` is ever
		// changed to print extra context on the same line, breaking the
		// "token never leaks past this helper" invariant.
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(trimmed, marker) {
			continue
		}
		return strings.TrimSpace(trimmed[len(marker):])
	}
	return ""
}

// redact strips occurrences of the secret from buf so the result is safe
// to include in test logs. Used on `docker exec` output that may echo the
// HOOKS_TOKEN env we passed in.
func redact(buf []byte, secret string) []byte {
	if secret == "" {
		return buf
	}
	return bytes.ReplaceAll(buf, []byte(secret), []byte("[REDACTED]"))
}

// tokenListContainsName checks for `name` as a whitespace-anchored field in
// `hooksctl token list` output. Substring matching would over-accept a
// future header or help banner that mentions the same word.
func tokenListContainsName(out []byte, name string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		for _, field := range strings.Fields(line) {
			if field == name {
				return true
			}
		}
	}
	return false
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

// shutdownDeadline mirrors the WithTimeout value in cmd/hooks/main.go's
// signal-handler goroutine. Kept in sync by the SIGTERM test below — if the
// binary's deadline ever changes, update this too.
const shutdownDeadline = 30 * time.Second

// TestImageGracefulShutdownOnSIGTERM verifies that `docker stop` (which
// sends SIGTERM, then SIGKILL after a grace period) lets the binary exit
// cleanly via its signal.NotifyContext path rather than getting hard-killed.
// A failed graceful shutdown shows up as exit code 137 (128 + SIGKILL) and
// `docker stop` taking the full grace period; a successful one returns
// quickly with exit code 0. The container is started without --rm so we
// can read .State.ExitCode after stop; cleanup goes through cleanupContainer
// rather than relying on the daemon to remove it.
func TestImageGracefulShutdownOnSIGTERM(t *testing.T) {
	skipIfNoDocker(t)
	dir := scaffoldDataDir(t)

	name := fmt.Sprintf("hooks-dockertest-sigterm-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupContainer(t, name) })

	if out, err := exec.Command("docker", "run", "-d",
		"--name", name,
		"-v", dir+":/data",
		"-e", "RENDER_WEBHOOK_SECRET=stub-for-tests",
		"-p", "0:8080",
		imageTag,
	).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}

	addr := "http://127.0.0.1:" + hostPort(t, name, "8080/tcp")
	if err := waitForHealthz(addr, 60*time.Second); err != nil {
		t.Fatalf("server: %v\nlogs:\n%s", err, dockerLogs(name))
	}

	// `docker stop -t` exceeds shutdownDeadline by 5s so a slow CI runner
	// doesn't SIGKILL a graceful-but-slow shutdown.
	stopGrace := shutdownDeadline + 5*time.Second
	start := time.Now()
	if out, err := exec.Command("docker", "stop", "-t",
		fmt.Sprintf("%d", int(stopGrace.Seconds())), name).CombinedOutput(); err != nil {
		t.Fatalf("docker stop: %v\n%s", err, out)
	}
	elapsed := time.Since(start)

	out, err := exec.Command("docker", "inspect",
		"--format", "{{.State.ExitCode}}",
		name,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker inspect: %v\n%s", err, out)
	}
	code := strings.TrimSpace(string(out))
	if code != "0" {
		t.Fatalf("graceful shutdown failed: exit=%s after %v\nlogs:\n%s",
			code, elapsed, dockerLogs(name))
	}
	if elapsed > shutdownDeadline {
		t.Fatalf("docker stop took %v, longer than the binary's %v shutdown deadline",
			elapsed, shutdownDeadline)
	}
}

// TestImageHooksctlAgainstRunningServer boots the server in the container
// and runs `hooksctl token list` from inside the same container against
// 127.0.0.1:8080. Proves the shipped hooksctl can talk to the shipped hooks
// over a real TCP loopback inside the image — a property unit tests can't
// cover because they swap in httptest servers and a host-built hooksctl.
//
// The admin token is captured from `hooks init` and passed to docker exec
// via -e HOOKS_TOKEN= so it never lands in argv (and never in the test
// log; we redact before printing failure output).
func TestImageHooksctlAgainstRunningServer(t *testing.T) {
	skipIfNoDocker(t)
	dir, token := scaffoldDataDirCapturingToken(t)

	name := fmt.Sprintf("hooks-dockertest-ctl-%d", time.Now().UnixNano())
	// Register cleanup before the run so a failure between the two lines
	// can't leak the container; `docker rm -f` on a not-yet-created name
	// is a harmless no-op (logged by cleanupContainer).
	t.Cleanup(func() { cleanupContainer(t, name) })
	if out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", name,
		"-v", dir+":/data",
		"-e", "RENDER_WEBHOOK_SECRET=stub-for-tests",
		"-p", "0:8080",
		imageTag,
	).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}

	addr := "http://127.0.0.1:" + hostPort(t, name, "8080/tcp")
	if err := waitForHealthz(addr, 60*time.Second); err != nil {
		t.Fatalf("server: %v\nlogs:\n%s", err, dockerLogs(name))
	}

	// HOOKS_SERVER targets the in-container listener port (8080, EXPOSEd by
	// the Dockerfile), not the random host-mapped port — exec runs inside
	// the container's network namespace.
	cmd := exec.Command("docker", "exec",
		"-e", "HOOKS_TOKEN="+token,
		"-e", "HOOKS_SERVER=http://127.0.0.1:8080",
		name,
		"hooksctl", "token", "list",
	)
	out, err := cmd.CombinedOutput()
	safe := redact(out, token)
	if err != nil {
		t.Fatalf("hooksctl token list: %v\n%s\nlogs:\n%s", err, safe, dockerLogs(name))
	}
	// `hooks init` mints the admin token under the default name "operator".
	// Anchor with whitespace boundaries so a future header rename or help
	// banner that happens to contain "operator" can't satisfy this.
	if !tokenListContainsName(out, "operator") {
		t.Fatalf("token list missing the operator-named admin token\noutput:\n%s", safe)
	}
}

// TestImageInitFailsClearlyOn0o755HostDir documents what an operator hits
// when they follow the README literally — `mkdir -p ./hooks-data` produces
// a 0o755 directory owned by their host user. The container runs as UID
// 65532 (non-root), so bind-mount writes inside /data hit EACCES. We don't
// try to "fix" this in the image (chowning /data inside the container
// would require running as root or an init script); we test that the
// failure is loud (non-zero exit, "permission denied" in stderr).
//
// Skips on platforms that translate UIDs across the bind mount (Docker
// Desktop with file sharing typically does this on macOS) — there the
// scenario doesn't manifest, so there's nothing to assert. The probe runs
// `touch /data/probe` from inside the container against a 0o755 host dir
// and skips if the touch succeeds.
func TestImageInitFailsClearlyOn0o755HostDir(t *testing.T) {
	skipIfNoDocker(t)
	dir := t.TempDir()
	// Force 0o755 to model the README path exactly (`mkdir -p ./hooks-data`
	// with default umask 022). t.TempDir defaults to 0o700 — both block a
	// non-owner UID, but 0o755 is the failure operators actually report.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}

	probe, err := exec.Command("docker", "run", "--rm",
		"-v", dir+":/data",
		"--entrypoint", "sh",
		imageTag, "-c", "touch /data/probe",
	).CombinedOutput()
	if err == nil {
		t.Skipf("docker bind mount allows non-owner writes on this host "+
			"(likely a UID-translating setup like Docker Desktop file sharing); "+
			"the README permissions edge case doesn't manifest here.\nprobe output: %s", probe)
	}

	out, runErr := exec.Command("docker", "run", "--rm",
		"-v", dir+":/data",
		imageTag, "init",
	).CombinedOutput()
	if runErr == nil {
		t.Fatalf("expected `hooks init` to fail on a 0o755 host dir, but it succeeded:\n%s", out)
	}
	if !bytes.Contains(bytes.ToLower(out), []byte("permission denied")) {
		t.Fatalf("expected permission-denied error in init output, got:\n%s", out)
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

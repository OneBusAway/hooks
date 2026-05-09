// Package dockertest exercises the project Dockerfile end-to-end —
// builds the image, then runs targeted assertions against it (help
// output, non-root UID, init scaffold, /healthz + /readyz, HEALTHCHECK
// directive, restart-with-persisted-state).
//
// Tests are gated by the `docker` build tag so the slow image build does
// not run on every `go test ./...`. Run locally with `make docker-test`
// before shipping any image change; CI deliberately doesn't (a Docker job
// would add minutes to every push for a relay that already has fast-running
// in-process server tests).
package dockertest

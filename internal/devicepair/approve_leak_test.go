package devicepair

import (
	"os"
	"regexp"
	"testing"
)

// TestApprove_500BodyDoesNotLeakRawError is the regression for the
// security fix: the approve handler must not concatenate err.Error()
// into a JSON response body. Today's leak vector was a literal
// `"approve: " + err.Error()` -- a future fmt.Errorf("scopes %q", ...)
// inside the tx would leak token plaintext via that path.
//
// The dynamic flow that triggers the buggy code path (start ->
// password-verify -> GetByUserCode -> pending check -> scope check
// -> ApproveDevicePairing FAILS) requires racing the DB to fail at
// exactly that step, which is brittle. Instead this is a source-shape
// regression: any err.Error() concatenation into a 500 response body
// inside api.go's approve handler fails the test.
func TestApprove_500BodyDoesNotLeakRawError(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	// The exact leak signature (any prefix concatenated with err.Error()
	// inside a writeJSON map-literal value).
	leakRE := regexp.MustCompile(`writeJSON\([^,]+,\s*http\.StatusInternalServerError,\s*map\[string\]string\{\s*"error":\s*"[^"]*"\s*\+\s*err\.Error\(\)`)
	if loc := leakRE.FindIndex(src); loc != nil {
		t.Errorf("approve handler concatenates err.Error() into a 500 body at byte offset %d-%d; "+
			"replace with the generic \"internal\" message and route the err through Logger.WarnContext",
			loc[0], loc[1])
	}
}

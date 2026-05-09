package main

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
)

// captureStdout replaces os.Stdout for the duration of fn and returns the
// bytes written. The pipe is drained on a separate goroutine so very chatty
// callers do not deadlock against a full pipe buffer.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&buf, r)
	}()

	code := fn()
	_ = w.Close()
	os.Stdout = old
	wg.Wait()
	_ = r.Close()
	return buf.String(), code
}

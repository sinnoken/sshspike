package main

import (
	"strings"
	"testing"
)

// capped is the only piece of custom stream logic here, and a bug in it would
// silently truncate or leak memory, so it gets a test.
func TestCappedTruncates(t *testing.T) {
	c := &capped{limit: 10}

	n, err := c.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write = (%d, %v), want (5, nil)", n, err)
	}
	if c.cut {
		t.Error("should not be marked truncated yet")
	}

	// Writing past the limit must report full consumption so the SSH session
	// keeps draining, while only the first 10 bytes are retained.
	n, err = c.Write([]byte(strings.Repeat("x", 100)))
	if err != nil || n != 100 {
		t.Fatalf("Write = (%d, %v), want (100, nil)", n, err)
	}
	if !c.cut {
		t.Error("should be marked truncated")
	}
	if got := c.b.String(); got != "helloxxxxx" {
		t.Fatalf("buffer = %q, want %q", got, "helloxxxxx")
	}
}

func TestPoolKeyIsStable(t *testing.T) {
	if a, b := key("ops", "10.0.0.1", 22), key("ops", "10.0.0.1", 22); a != b {
		t.Fatalf("key not stable: %q vs %q", a, b)
	}
	// User and port must both participate, otherwise the pool would hand back
	// a connection authenticated as the wrong user.
	if key("ops", "10.0.0.1", 22) == key("root", "10.0.0.1", 22) {
		t.Error("user must be part of the pool key")
	}
	if key("ops", "10.0.0.1", 22) == key("ops", "10.0.0.1", 2222) {
		t.Error("port must be part of the pool key")
	}
}

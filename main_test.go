package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// capped is the only piece of custom stream logic here, and a bug in it would
// silently truncate output or let a runaway command exhaust memory.
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

func TestCappedExactLimit(t *testing.T) {
	c := &capped{limit: 5}
	if _, err := c.Write([]byte("abcde")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !c.cut {
		t.Error("reaching the limit exactly should mark truncation")
	}
	if got := c.b.String(); got != "abcde" {
		t.Fatalf("buffer = %q, want %q", got, "abcde")
	}
}

func TestPoolKeyIsStable(t *testing.T) {
	if a, b := key("ops", "10.0.0.1", 22), key("ops", "10.0.0.1", 22); a != b {
		t.Fatalf("key not stable: %q vs %q", a, b)
	}
	// User and port must both participate, otherwise the pool could hand back
	// a connection authenticated as the wrong user.
	if key("ops", "10.0.0.1", 22) == key("root", "10.0.0.1", 22) {
		t.Error("user must be part of the pool key")
	}
	if key("ops", "10.0.0.1", 22) == key("ops", "10.0.0.1", 2222) {
		t.Error("port must be part of the pool key")
	}
}

func TestHostKeyVerifierRequiresASource(t *testing.T) {
	if _, err := newHostKeyVerifier("", false); err == nil {
		t.Fatal("an empty known_hosts path must be rejected")
	}
	if _, err := newHostKeyVerifier("/nonexistent/known_hosts", false); err == nil {
		t.Fatal("a missing known_hosts file must be rejected")
	}
	// The escape hatch is explicit and opt-in.
	if _, err := newHostKeyVerifier("", true); err != nil {
		t.Fatalf("-insecure-host-key should bypass the check: %v", err)
	}
}

func newTestServer() *Server {
	return &Server{
		pool:        &Pool{verify: ssh.InsecureIgnoreHostKey(), maxOutput: 1 << 20},
		defaultUser: "tester",
	}
}

func post(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	return w
}

func TestIndexServesConsole(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ssh spike") {
		t.Error("console title missing")
	}
	// The username placeholder must be substituted, not shipped verbatim.
	if strings.Contains(body, "{{USER}}") {
		t.Error("username placeholder was not substituted")
	}
	if !strings.Contains(body, `value="tester"`) {
		t.Error("default user was not injected into the form")
	}
}

func TestUnknownPathIs404(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestRunValidatesInput(t *testing.T) {
	s := newTestServer()

	cases := []struct {
		name string
		body string
		want int
	}{
		{"missing host", `{"command":"echo hi"}`, http.StatusBadRequest},
		{"blank host", `{"host":"   ","command":"echo hi"}`, http.StatusBadRequest},
		{"missing command", `{"host":"10.0.0.1"}`, http.StatusBadRequest},
		{"blank command", `{"host":"10.0.0.1","command":"  "}`, http.StatusBadRequest},
		{"malformed json", `{"host":`, http.StatusBadRequest},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if w := post(t, s, "/api/run", c.body); w.Code != c.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, c.want, w.Body.String())
			}
		})
	}
}

func TestRunRejectsGET(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/run", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

// A dial failure must come back as a structured result, not a 500, so the
// console can render the error next to the timing it did manage to collect.
func TestRunReportsDialFailureAsResult(t *testing.T) {
	s := newTestServer()
	// Port 0 is reserved and never connectable.
	w := post(t, s, "/api/run", `{"host":"127.0.0.1","port":1,"command":"true","timeout_ms":500}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var res Result
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Error == "" {
		t.Fatal("expected an error message in the result")
	}
	if res.ExitCode != -1 {
		t.Errorf("exit_code = %d, want -1 for a failed dial", res.ExitCode)
	}
	if res.Reused {
		t.Error("a failed dial must not be reported as a reused connection")
	}
}

func TestConnsStartsEmpty(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/conns", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct {
		Connections []ConnView `json:"connections"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Connections) != 0 {
		t.Fatalf("expected an empty pool, got %d", len(body.Connections))
	}
}

// Without SSH_AUTH_SOCK the endpoint must fail cleanly rather than panic,
// because that is the state a fresh machine is in.
func TestIdentitiesWithoutAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	s := newTestServer()
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/identities", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body["error"], "SSH_AUTH_SOCK") {
		t.Errorf("error should name the missing variable, got %q", body["error"])
	}
}

func TestSignersWithoutAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := signers(); err == nil {
		t.Fatal("signers() must fail without an agent")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	s := newTestServer()
	// Closing a connection that was never opened should still succeed, so the
	// console button is safe to press at any time.
	for i := 0; i < 2; i++ {
		if w := post(t, s, "/api/close", `{"host":"10.0.0.1","port":22,"user":"ops"}`); w.Code != http.StatusOK {
			t.Fatalf("attempt %d: status = %d", i+1, w.Code)
		}
	}
}

// The pool is shared by concurrent HTTP handlers, so its bookkeeping must be
// safe under -race even when every request fails to dial.
func TestPoolConcurrentAccess(t *testing.T) {
	s := newTestServer()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			post(t, s, "/api/run", `{"host":"127.0.0.1","port":1,"command":"true","timeout_ms":300}`)
			s.pool.list()
			s.pool.drop("tester", "127.0.0.1", 1)
		}()
	}
	wg.Wait()

	s.pool.CloseAll()
	if got := len(s.pool.list()); got != 0 {
		t.Fatalf("pool should be empty after CloseAll, got %d", got)
	}
}

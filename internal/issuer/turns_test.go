package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-calls/internal/turnsstatus"
)

const (
	udp   = "turn:turn.staging.vettid.org:3478?transport=udp"
	tcp   = "turn:turn.staging.vettid.org:3478?transport=tcp"
	turns = "turns:turn.staging.vettid.org:443?transport=tcp"
)

// status is a settable TLS status source.
type status struct {
	mu  sync.Mutex
	b   []byte
	err error
}

func (s *status) set(b []byte, err error) { s.mu.Lock(); s.b, s.err = b, err; s.mu.Unlock() }
func (s *status) Get(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b, s.err
}

func (h *harness) turnURLs() string {
	h.t.Helper()
	body := h.expect("credentials", h.request(req{}), 200, "")
	var a Answer
	if err := json.Unmarshal(body, &a); err != nil {
		h.t.Fatal(err)
	}
	return strings.Join(a.TURN, ",")
}

// TLS switched off: no turns: URL and no turns_listed metric.
func TestTURNSOff(t *testing.T) {
	h := newHarness(t, nil)
	if got := h.turnURLs(); got != udp+","+tcp {
		t.Fatal(got)
	}
	_, data := h.reg.Take()
	for _, d := range data {
		if d.Name == "turns_listed" {
			t.Fatal("turns_listed put while TLS is off")
		}
	}
}

// TLS switched on: turns: is listed only while the status is fresh
// (CALLING-SERVICE 0.3.0 §8.5), and the status never fails a request.
func TestTURNSListedWhileFresh(t *testing.T) {
	src := &status{}
	var h *harness
	h = newHarness(t, func(c *Config) {
		c.TURNS = &turnsstatus.Holder{Source: src, Now: func() time.Time { return h.clk.Now() }}
	})
	end := t0.Add(60 * 24 * time.Hour).Unix()
	src.set(turnsstatus.Status{VerifiedAt: t0.Unix(), NotAfter: end}.Encode(), nil)

	if got := h.turnURLs(); got != udp+","+tcp+","+turns {
		t.Fatal(got)
	}
	if h.reg.Value("turns_listed") != 1 {
		t.Fatal("turns_listed not 1")
	}
	// The server's base list is not changed by an answer.
	if strings.Join(h.srv.turn, ",") != udp+","+tcp {
		t.Fatal(h.srv.turn)
	}

	// 24 minutes later the holder reads again and gets the same value:
	// still fresh.
	h.clk.Set(t0.Add(24 * time.Minute))
	if got := h.turnURLs(); !strings.HasSuffix(got, turns) {
		t.Fatal("not listed at 24 min", got)
	}
	// The server stops refreshing (a failed handshake writes nothing):
	// at 25 minutes the same value is no longer fresh, at request time.
	h.clk.Set(t0.Add(25 * time.Minute))
	if got := h.turnURLs(); got != udp+","+tcp {
		t.Fatal("listed at 25 min", got)
	}
	if h.reg.Value("turns_listed") != 0 {
		t.Fatal("turns_listed not 0")
	}

	// Refreshed again; then the parameter cannot be read: the last value
	// is kept, still aged.
	h.clk.Set(t0.Add(40 * time.Minute))
	src.set(turnsstatus.Status{VerifiedAt: h.clk.Now().Unix(), NotAfter: end}.Encode(), nil)
	if got := h.turnURLs(); !strings.HasSuffix(got, turns) {
		t.Fatal("not listed after a refresh", got)
	}
	src.set(nil, errors.New("network"))
	h.clk.Set(t0.Add(51 * time.Minute))
	if got := h.turnURLs(); !strings.HasSuffix(got, turns) {
		t.Fatal("a failed read dropped a fresh status", got)
	}
	h.clk.Set(t0.Add(65 * time.Minute))
	if got := h.turnURLs(); got != udp+","+tcp {
		t.Fatal("a kept status was not aged", got)
	}

	// Malformed, missing, far-future and ended certificates: not listed,
	// and each request still answers 200.
	for name, v := range map[string]func(){
		"malformed": func() { src.set([]byte(`{"verified_at":1}`), nil) },
		"missing":   func() { src.set(nil, turnsstatus.ErrNotFound) },
		"far future": func() {
			src.set(turnsstatus.Status{VerifiedAt: h.clk.Now().Add(time.Hour).Unix(), NotAfter: end}.Encode(), nil)
		},
		"cert ended": func() {
			src.set(turnsstatus.Status{VerifiedAt: h.clk.Now().Unix(), NotAfter: h.clk.Now().Unix()}.Encode(), nil)
		},
		"zero status": func() { src.set(turnsstatus.Status{}.Encode(), nil) },
	} {
		h.clk.Set(h.clk.Now().Add(11 * time.Minute))
		v()
		if got := h.turnURLs(); got != udp+","+tcp {
			t.Fatalf("%s: listed: %s", name, got)
		}
	}
	if h.reg.Value("internal_errors") != 0 {
		t.Fatal("the status counted as internal")
	}
}

// The first read failing: not listed, and the request answers.
func TestTURNSFirstReadFails(t *testing.T) {
	src := &status{err: errors.New("network")}
	h := newHarness(t, func(c *Config) { c.TURNS = &turnsstatus.Holder{Source: src} })
	if got := h.turnURLs(); got != udp+","+tcp {
		t.Fatal(got)
	}
}

// Warm reads the status before the first request.
func TestTURNSWarm(t *testing.T) {
	src := &countingStatus{}
	h := newHarness(t, func(c *Config) { c.TURNS = &turnsstatus.Holder{Source: src} })
	h.srv.Warm(context.Background())
	if src.n != 1 {
		t.Fatalf("%d reads at Warm", src.n)
	}
}

type countingStatus struct{ n int }

func (c *countingStatus) Get(context.Context) ([]byte, error) {
	c.n++
	return nil, turnsstatus.ErrNotFound
}

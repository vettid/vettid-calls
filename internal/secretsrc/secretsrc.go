// Package secretsrc reads the TURN shared secret's document
// (CALLING-SERVICE §8.3) and keeps the last good copy in memory. Nothing
// is ever written back, nothing logs, and no error carries the content.
//
// The AWS Secrets Manager source lives in internal/awsx; this package
// holds the file and environment sources and the holder both binaries
// use. The issuer and turn-agent read the secret when they start and
// again every 10 minutes (§8.3).
package secretsrc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vettid/vettid-calls/internal/turncred"
)

// RefreshInterval is how often the secret is read again (§8.3).
const RefreshInterval = 10 * time.Minute

// RetryInterval is the least time between two failed reads.
const RetryInterval = time.Minute

// ErrNotFound is a secret the source does not have.
var ErrNotFound = errors.New("secretsrc: secret not found")

// Source reads the secret document.
type Source interface {
	Get(ctx context.Context) ([]byte, error)
}

// File reads the document from a file (self-hosting, development).
type File string

// Get implements Source.
func (f File) Get(context.Context) ([]byte, error) {
	b, err := os.ReadFile(string(f))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNotFound
	case err != nil:
		return nil, errors.New("secretsrc: reading the secret file failed")
	case len(b) > turncred.MaxDocument:
		return nil, errors.New("secretsrc: the secret file is too large")
	}
	return b, nil
}

// Env reads the document from an environment variable.
type Env struct {
	Name   string
	Lookup func(string) (string, bool)
}

// Get implements Source.
func (e Env) Get(context.Context) ([]byte, error) {
	v, ok := e.Lookup(e.Name)
	if !ok || v == "" {
		return nil, ErrNotFound
	}
	return []byte(v), nil
}

// Static is a fixed document (tests, the dev stand-in).
type Static []byte

// Get implements Source.
func (s Static) Get(context.Context) ([]byte, error) { return s, nil }

// Holder keeps the last good secret document and reads it again when it
// is RefreshInterval old by the wall clock (the issuer may be a function
// frozen between requests, so no background timer is relied on).
type Holder struct {
	Source Source
	// Now is the clock (default: the wall clock without its monotonic
	// reading).
	Now func() time.Time
	// Report, if set, is told the outcome of every read.
	Report func(error)

	mu          sync.Mutex
	set         *turncred.Set
	loaded      time.Time
	lastAttempt time.Time
	changed     bool
}

func (h *Holder) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().Round(0)
}

// Load reads the document now; on failure the previous one stays.
func (h *Holder) Load(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.loadLocked(ctx)
}

func (h *Holder) loadLocked(ctx context.Context) error {
	now := h.now()
	h.lastAttempt = now
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := h.Source.Get(rctx)
	if err == nil {
		var s *turncred.Set
		s, err = turncred.ParseSet(b)
		if err == nil {
			if !s.Equal(h.set) {
				h.changed = h.set != nil || h.changed
				h.set = s
			}
			h.loaded = now
		}
	}
	if err != nil {
		err = fmt.Errorf("secretsrc: %w", err)
	}
	if h.Report != nil {
		h.Report(err)
	}
	return err
}

// Get returns the current document, reading it first if none is held or
// the held one is RefreshInterval old. It returns nil only if no read has
// ever succeeded.
func (h *Holder) Get(ctx context.Context) *turncred.Set {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	fresh := h.set != nil && now.Sub(h.loaded) < RefreshInterval && now.Sub(h.loaded) >= 0
	retryOK := h.lastAttempt.IsZero() || now.Sub(h.lastAttempt) >= RetryInterval || now.Before(h.lastAttempt)
	if !fresh && retryOK {
		_ = h.loadLocked(ctx)
	}
	return h.set
}

// Changed reports, once, whether a read replaced a document held before
// (turn-agent restarts coturn then).
func (h *Holder) Changed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.changed
	h.changed = false
	return c
}

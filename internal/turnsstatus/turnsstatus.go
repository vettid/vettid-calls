// Package turnsstatus is the TURN server's TLS status, which turn-agent
// puts and the issuer reads (CALLING-SERVICE 0.3.0 §8.5 "The status for
// the issuer"): whether coturn served a verified certificate on 443
// lately, so that the issuer lists a turns: URL only when it works.
//
// The value is not a secret: {"verified_at": <Unix s>, "not_after": <Unix
// s>}. It is parsed strictly, and anything missing or malformed means
// "not verified"; the issuer never fails a request over it.
package turnsstatus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	// MaxSize bounds the value.
	MaxSize = 256
	// MaxAge is how long a verification counts.
	MaxAge = 25 * time.Minute
	// MaxAhead is how far a verified_at may be ahead of the reader's
	// clock; beyond it the value is refused, so that a far-future value
	// cannot stay fresh.
	MaxAhead = 5 * time.Minute
	// RefreshInterval is how often the issuer reads it again (with its
	// secret, §8.3).
	RefreshInterval = 10 * time.Minute
	// RetryInterval is the least time between two failed reads.
	RetryInterval = time.Minute
	// ReadTimeout bounds a read: it is made on a request's path, and a
	// call never waits long for the issuer (§5.4).
	ReadTimeout = time.Second

	maxInt = 1 << 53
)

// ErrNotFound is a status the source does not have.
var ErrNotFound = errors.New("turnsstatus: not found")

// The outcomes of a read, as Holder.Report gets them.
const (
	OutcomeOK        = "ok"        // a value that parses
	OutcomeMissing   = "missing"   // no value: not verified
	OutcomeMalformed = "malformed" // a value that does not parse: not verified
	OutcomeFuture    = "future"    // verified_at more than MaxAhead ahead: refused, not verified
	OutcomeError     = "error"     // the read failed: the last status is kept
)

// Status is the value. The zero Status is "not verified".
type Status struct {
	VerifiedAt int64 // Unix seconds of the last verified handshake; 0: none
	NotAfter   int64 // Unix seconds of the served certificate's end
}

// Encode returns the value's one form.
func (s Status) Encode() []byte {
	return fmt.Appendf(nil, `{"verified_at":%d,"not_after":%d}`, s.VerifiedAt, s.NotAfter)
}

// Fresh reports whether s says a turns: URL works at now: verified less
// than MaxAge ago, not more than MaxAhead in the future, and the
// certificate not yet ended.
func (s Status) Fresh(now time.Time) bool {
	if s.VerifiedAt <= 0 {
		return false
	}
	v := time.Unix(s.VerifiedAt, 0)
	return now.Sub(v) < MaxAge && v.Sub(now) <= MaxAhead && now.Before(time.Unix(s.NotAfter, 0))
}

// Parse accepts exactly a JSON object with the two integer members
// verified_at and not_after (0 to 2^53), once each, and nothing else.
func Parse(b []byte) (Status, error) {
	bad := errors.New("turnsstatus: malformed")
	if len(b) == 0 || len(b) > MaxSize {
		return Status{}, bad
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return Status{}, bad
	}
	var s Status
	seen := map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		name, ok := k.(string)
		if err != nil || !ok || seen[name] {
			return Status{}, bad
		}
		seen[name] = true
		v, err := dec.Token()
		num, ok := v.(json.Number)
		if err != nil || !ok {
			return Status{}, bad
		}
		n, err := strconv.ParseInt(string(num), 10, 64)
		if err != nil || n < 0 || n > maxInt {
			return Status{}, bad
		}
		switch name {
		case "verified_at":
			s.VerifiedAt = n
		case "not_after":
			s.NotAfter = n
		default:
			return Status{}, bad
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') || len(seen) != 2 {
		return Status{}, bad
	}
	if _, err := dec.Token(); err != io.EOF {
		return Status{}, bad
	}
	return s, nil
}

// Source reads the value.
type Source interface {
	Get(ctx context.Context) ([]byte, error)
}

// Holder keeps the status the issuer last read, and reads it again when
// it is RefreshInterval old by the wall clock (the issuer may be a
// function frozen between requests, so no background timer is relied
// on).
//
// A read that answers settles the status: a value that parses is it;
// one that is missing (ErrNotFound), does not parse, or is verified more
// than MaxAhead ahead of the clock is "not verified" (a future value is
// refused, not kept until the clock catches up). A read that fails keeps
// the last status.
type Holder struct {
	Source Source
	// Now is the clock (default: the wall clock without its monotonic
	// reading).
	Now func() time.Time
	// Report, if set, is told every read: the status held after it, the
	// outcome (Outcome*), and the error of a failed read.
	Report func(st Status, outcome string, err error)

	mu          sync.Mutex
	st          Status
	loaded      time.Time
	lastAttempt time.Time
}

func (h *Holder) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().Round(0)
}

// Get returns the status, reading it first when none was read or the one
// held is RefreshInterval old.
func (h *Holder) Get(ctx context.Context) Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	fresh := !h.loaded.IsZero() && now.Sub(h.loaded) < RefreshInterval && now.Sub(h.loaded) >= 0
	retryOK := h.lastAttempt.IsZero() || now.Sub(h.lastAttempt) >= RetryInterval || now.Before(h.lastAttempt)
	if !fresh && retryOK {
		h.loadLocked(ctx, now)
	}
	return h.st
}

func (h *Holder) loadLocked(ctx context.Context, now time.Time) {
	h.lastAttempt = now
	rctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	b, err := h.Source.Get(rctx)
	outcome := OutcomeOK
	switch {
	case errors.Is(err, ErrNotFound):
		h.st, h.loaded, err, outcome = Status{}, now, nil, OutcomeMissing
	case err != nil:
		// Kept: the last status, still aged by Fresh.
		outcome = OutcomeError
	default:
		st, perr := Parse(b)
		switch {
		case perr != nil:
			st, outcome = Status{}, OutcomeMalformed
		case time.Unix(st.VerifiedAt, 0).Sub(now) > MaxAhead:
			st, outcome = Status{}, OutcomeFuture
		}
		h.st, h.loaded = st, now
	}
	if h.Report != nil {
		h.Report(h.st, outcome, err)
	}
}

// File reads the value from a file (self-hosting, development).
type File string

// Get implements Source.
func (f File) Get(context.Context) ([]byte, error) {
	b, err := os.ReadFile(string(f))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNotFound
	case err != nil:
		return nil, errors.New("turnsstatus: reading the status file failed")
	}
	return b, nil
}

// Static is a fixed value (tests, self-hosting without a parameter).
type Static []byte

// Get implements Source.
func (s Static) Get(context.Context) ([]byte, error) { return s, nil }

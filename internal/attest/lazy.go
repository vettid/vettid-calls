package attest

// vettid-calls: this file is not in vettid-push. The issuer may run as a
// function that is frozen between requests (CALLING-SERVICE §5.2, §8.2),
// so it cannot rely on a background loop (Manifests.Run) or on the
// monotonic clock: it refreshes the manifest on the request path when the
// last successful refresh is RefreshInterval old by the wall clock.

import (
	"context"
	"sync"
	"time"
)

// WallClock is time.Now without its monotonic reading, so that ages are
// measured on the wall clock (§5.2: "the manifest's age is measured on the
// wall clock, since an issuer that runs as a function is frozen between
// requests"). Set Manifests.Now to it.
func WallClock() time.Time { return time.Now().Round(0) }

// RetryInterval is the least time between two refresh attempts that
// failed, so a manifest site that is down is not fetched on every request.
const RetryInterval = time.Minute

// Lazy refreshes a Manifests on demand.
type Lazy struct {
	M *Manifests
	// Interval is how old the last successful refresh may be before a
	// request triggers another (default RefreshInterval).
	Interval time.Duration
	// Report, if set, is told the outcome of every attempt.
	Report func(error)

	mu          sync.Mutex
	lastAttempt time.Time
}

// due reports whether a refresh should be attempted now.
func (l *Lazy) due(now time.Time) bool {
	interval := l.Interval
	if interval <= 0 {
		interval = RefreshInterval
	}
	l.M.mu.RLock()
	serial, refreshed := l.M.serial, l.M.refreshed
	l.M.mu.RUnlock()
	if serial != 0 && now.Sub(refreshed) < interval && now.Sub(refreshed) >= 0 {
		return false
	}
	return l.lastAttempt.IsZero() || now.Sub(l.lastAttempt) >= RetryInterval || now.Before(l.lastAttempt)
}

// Ensure refreshes the manifest if it is due. While no manifest has been
// trusted yet, callers wait for an attempt in flight; otherwise a caller
// that finds an attempt in flight goes on with the manifest it has. The
// previous manifest stays trusted on failure, up to MaxManifestAge
// (Manifests.Refresh).
func (l *Lazy) Ensure(ctx context.Context) {
	if l.M.Serial() == 0 {
		l.mu.Lock()
	} else if !l.mu.TryLock() {
		return
	}
	defer l.mu.Unlock()
	now := l.M.now()
	if !l.due(now) {
		return
	}
	l.lastAttempt = now
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := l.M.Refresh(rctx)
	if l.Report != nil {
		l.Report(err)
	}
}

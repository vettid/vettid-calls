// Package issuer is the credential issuer's HTTP surface
// (CALLING-SERVICE §5.2): POST /v1/credentials and GET /v1/health.
//
// It keeps no state and writes nothing: no replay cache, no record of a
// request, no per-vault count (§5.2, §7.5). It logs errors of the service
// itself, throttled, and never a key, an attestation document, a
// username, a credential or a source address (§10). It does not read the
// source address at all.
package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-calls/internal/attest"
	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/turncred"
)

// Paths.
const (
	PathCredentials = "/v1/credentials"
	PathHealth      = "/v1/health"
)

// HeaderAttestation carries the Nitro attestation document (as for the
// push gateway, PUSH-GATEWAY §5.1).
const HeaderAttestation = "X-VettID-Attestation"

// MaxBody bounds a request body (§5.2: at most 1 KiB).
const MaxBody = 1024

// MaxCount is the most credentials one request may ask for (§5.2).
const MaxCount = 4

// DefaultMaxInFlight is the number of requests handled at once on staging
// (§7.5); more are answered 429.
const DefaultMaxInFlight = 4

// TURNPort is the port of STUN and TURN (§4.3).
const TURNPort = 3478

// Config configures a Server.
type Config struct {
	// Attest verifies the attestation (step 2).
	Attest *attest.Verifier
	// Manifest, if set, refreshes the trusted manifest on the request
	// path before an attestation is verified (a function is frozen
	// between requests, so no background loop is relied on).
	Manifest *attest.Lazy
	// Secrets holds the shared secret's document.
	Secrets *secretsrc.Holder
	// TURNHost is the TURN/STUN server's name (turn.staging.vettid.org).
	TURNHost string
	// MaxInFlight bounds the requests handled at once (§7.5).
	MaxInFlight int
	// Lifetime of a credential (default turncred.Lifetime, D14).
	Lifetime time.Duration
	Metrics  *metrics.Registry
	Log      *slog.Logger
	// Now is the clock (default: the wall clock).
	Now func() time.Time
	// Rand is the random source of usernames (default crypto/rand).
	Rand io.Reader
}

// Server is the issuer's http.Handler.
type Server struct {
	cfg      Config
	inflight chan struct{}
	stun     []string
	turn     []string

	logMu   sync.Mutex
	logLast map[string]time.Time
	logSkip map[string]int
}

// Answer is the body of a 200 answer to POST /v1/credentials.
type Answer struct {
	STUN        []string              `json:"stun"`
	TURN        []string              `json:"turn"`
	Credentials []turncred.Credential `json:"credentials"`
}

// New returns a server.
func New(cfg Config) (*Server, error) {
	if cfg.Attest == nil || cfg.Secrets == nil {
		return nil, errors.New("issuer: an attestation verifier and a secret holder are required")
	}
	if err := ValidHost(cfg.TURNHost); err != nil {
		return nil, err
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = DefaultMaxInFlight
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = turncred.Lifetime
	}
	if cfg.Lifetime > turncred.Lifetime {
		return nil, errors.New("issuer: a credential lives at most 6 hours (D14)")
	}
	if cfg.Now == nil {
		cfg.Now = attest.WallClock
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.New("vettid-calls", cfg.Now)
	}
	hp := net.JoinHostPort(cfg.TURNHost, strconv.Itoa(TURNPort))
	return &Server{cfg: cfg, inflight: make(chan struct{}, cfg.MaxInFlight),
		stun:    []string{"stun:" + hp},
		turn:    []string{"turn:" + hp + "?transport=udp", "turn:" + hp + "?transport=tcp"},
		logLast: map[string]time.Time{}, logSkip: map[string]int{}}, nil
}

// ValidHost accepts a DNS name of letters, digits, hyphens and dots (the
// URLs it goes into pass the vault's checks: no spaces or control
// characters, at most 512 bytes; VAULT-MESSAGING §10.10).
func ValidHost(h string) error {
	if h == "" || len(h) > 253 || h[0] == '.' || h[len(h)-1] == '.' {
		return errors.New("issuer: the TURN host must be a DNS name")
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return errors.New("issuer: the TURN host must be a lower-case DNS name")
		}
	}
	return nil
}

func dim(name, value string) metrics.Dim { return metrics.Dim{Name: name, Value: value} }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				panic(p)
			}
			// The panic's type only: its value could hold request data.
			s.logError("panic", "panic in handler", "type", fmt.Sprintf("%T", p))
			s.cfg.Metrics.Count("internal_errors")
			writeError(w, fail(CodeInternal))
		}
	}()
	switch {
	case r.URL.Path == PathHealth && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, struct{}{})
	case r.URL.Path == PathCredentials && r.Method == http.MethodPost:
		s.credentials(w, r)
	default:
		writeError(w, fail(CodeNotFound))
	}
}

func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	ans, e := s.handle(r)
	outcome := "ok"
	if e != nil {
		outcome = e.code
		if e.code == CodeInternal {
			s.cfg.Metrics.Count("internal_errors")
		}
		writeError(w, e)
	} else {
		writeJSON(w, http.StatusOK, ans)
	}
	s.cfg.Metrics.Count("requests", dim("outcome", outcome))
}

func (s *Server) handle(r *http.Request) (*Answer, *apiError) {
	// In total: at most MaxInFlight at once (§7.5).
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		return nil, &apiError{code: CodeRateLimited, retryAfter: 1}
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, MaxBody))
	if err != nil {
		return nil, fail(CodeBadRequest)
	}
	// 1. The signature and the 90 s window (RELAY-PROTOCOL §4.1). One
	// Ed25519 check is all an unsigned flood costs (§7.5).
	now := s.cfg.Now()
	sr, err := relayauth.ParseHeaders(r.Header)
	if err != nil {
		return nil, fail(CodeSignatureInvalid)
	}
	bodyHash := relayauth.BodyHash(body)
	if err := sr.Verify(http.MethodPost, PathCredentials, bodyHash, now); err != nil {
		if errors.Is(err, relayauth.ErrTimestampStale) {
			return nil, fail(CodeTimestampStale)
		}
		return nil, fail(CodeSignatureInvalid)
	}
	// 2. The attestation, with the rules of PUSH-GATEWAY §5.1 step 2
	// unchanged. Every failure is the same 403.
	if s.cfg.Manifest != nil {
		s.cfg.Manifest.Ensure(r.Context())
	}
	digest := relayauth.Digest(http.MethodPost, PathCredentials, sr.Timestamp, bodyHash)
	if err := s.cfg.Attest.Verify(r.Header.Values(HeaderAttestation), sr.Key, digest); err != nil {
		reason := string(attest.ReasonMalformed)
		var ae *attest.Error
		if errors.As(err, &ae) {
			reason = string(ae.Reason)
		}
		s.cfg.Metrics.Count("attestation_failures", dim("reason", reason))
		return nil, fail(CodeAttestationInvalid)
	}
	// 3. The body.
	count, ok := parseBody(body)
	if !ok {
		return nil, fail(CodeBadRequest)
	}
	// 4. count credentials under the current secret. Nothing is written.
	set := s.cfg.Secrets.Get(r.Context())
	if set == nil {
		s.logError("secret", "no TURN secret is available")
		return nil, fail(CodeInternal)
	}
	ans := &Answer{STUN: s.stun, TURN: s.turn, Credentials: make([]turncred.Credential, 0, count)}
	for i := 0; i < count; i++ {
		c, err := turncred.Make(set.CurrentSecret(), now, s.cfg.Lifetime, s.cfg.Rand)
		if err != nil {
			s.logError("random", "making a credential failed")
			return nil, fail(CodeInternal)
		}
		ans.Credentials = append(ans.Credentials, c)
	}
	return ans, nil
}

// parseBody accepts exactly {"count": n} with an integer 1 ≤ n ≤ 4: no
// other member and nothing after the object.
func parseBody(body []byte) (int, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req struct {
		Count *int `json:"count"`
	}
	if err := dec.Decode(&req); err != nil || req.Count == nil {
		return 0, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return 0, false
	}
	if *req.Count < 1 || *req.Count > MaxCount {
		return 0, false
	}
	return *req.Count, true
}

// logError logs an error of the service at most once a minute per kind,
// with the number left out since. Attributes are from closed sets; no
// request data reaches the log (§10).
func (s *Server) logError(kind, msg string, attrs ...any) {
	now := s.cfg.Now()
	s.logMu.Lock()
	if last, ok := s.logLast[kind]; ok && now.Sub(last) < time.Minute && now.Sub(last) >= 0 {
		s.logSkip[kind]++
		s.logMu.Unlock()
		return
	}
	skipped := s.logSkip[kind]
	s.logLast[kind], s.logSkip[kind] = now, 0
	s.logMu.Unlock()
	s.cfg.Log.Error(msg, append(attrs, "kind", kind, "suppressed_since_last", skipped)...)
}

// LogError is logError for the binary (refresh failures).
func (s *Server) LogError(kind, msg string, attrs ...any) { s.logError(kind, msg, attrs...) }

// Warm loads the secret and the manifest before the first request, so a
// cold start does not pay for both on the request path. Failures are
// reported through the holders' Report hooks.
func (s *Server) Warm(ctx context.Context) {
	_ = s.cfg.Secrets.Get(ctx)
	if s.cfg.Manifest != nil {
		s.cfg.Manifest.Ensure(ctx)
	}
}

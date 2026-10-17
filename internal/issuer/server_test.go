package issuer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/manifest"

	"github.com/vettid/vettid-calls/internal/attest"
	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/nsmtest"
	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/turncred"
)

const (
	secA   = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	secB   = "//////////////////////////////////////////8="
	secDoc = `{"current":"b","secrets":{"a":"` + secA + `","b":"` + secB + `"}}`
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// clock is a settable wall clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// harness is an issuer with a fake NSM, a manifest site serving a signed
// manifest, and the vault side of §5.2.
type harness struct {
	t       *testing.T
	clk     *clock
	nsm     *nsmtest.NSM
	signer  *nsmtest.ManifestSigner
	served  atomic.Value // []byte
	site    *httptest.Server
	fetches atomic.Int32
	m       *attest.Manifests
	reg     *metrics.Registry
	logs    *bytes.Buffer
	srv     *Server
}

func newHarness(t *testing.T, mut func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, clk: &clock{t: t0}, logs: &bytes.Buffer{}}
	// Certificates valid for the 8 days the manifest tests span.
	h.nsm = nsmtest.NewValid(0xa0, h.clk.Now, t0.Add(-24*time.Hour), t0.Add(8*24*time.Hour))
	h.signer = nsmtest.NewManifestSigner()
	// Releases in ascending order, as the manifest format requires.
	h.serve(5, nsmtest.Release(9, nsmtest.PCRHex(0xd0), manifest.StatusRemoved),
		nsmtest.Release(10, nsmtest.PCRHex(0xc0), manifest.StatusRetired),
		nsmtest.Release(11, nsmtest.PCRHex(0xb0), manifest.StatusDeprecated),
		nsmtest.Release(12, h.nsm.PCR0Hex(), manifest.StatusActive))
	h.site = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.fetches.Add(1)
		_, _ = w.Write(h.served.Load().([]byte))
	}))
	t.Cleanup(h.site.Close)
	h.m = &attest.Manifests{URL: h.site.URL, Keys: h.signer.Keys(), Now: h.clk.Now}
	h.reg = metrics.New("test", h.clk.Now)
	cfg := Config{
		Attest:   &attest.Verifier{Roots: h.nsm.Roots(), Releases: h.m, Now: h.clk.Now},
		Manifest: &attest.Lazy{M: h.m},
		Secrets:  &secretsrc.Holder{Source: secretsrc.Static(secDoc), Now: h.clk.Now},
		TURNHost: "turn.staging.vettid.org",
		Metrics:  h.reg,
		Log:      slog.New(slog.NewTextHandler(h.logs, nil)),
		Now:      h.clk.Now,
	}
	if mut != nil {
		mut(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	return h
}

func (h *harness) serve(serial uint64, rs ...manifest.Release) {
	h.served.Store(h.signer.Served(serial, rs...))
}

// req is one vault request (§5.2), built as the vault builds it: a fresh
// key, the RELAY-PROTOCOL §4.1 signature, and an attestation whose
// public_key is the key and whose user_data is the request's digest.
type req struct {
	body     []byte
	signAt   time.Time
	attestAt time.Time
	nsm      *nsmtest.NSM
	// attestKey and attestDigest override what the document binds.
	attestKey    ed25519.PublicKey
	attestDigest *[32]byte
	noAttest     bool
	path         string
}

func (h *harness) request(q req) *http.Request {
	h.t.Helper()
	if q.body == nil {
		q.body = []byte(`{"count":4}`)
	}
	if q.signAt.IsZero() {
		q.signAt = h.clk.Now()
	}
	if q.attestAt.IsZero() {
		q.attestAt = h.clk.Now()
	}
	if q.nsm == nil {
		q.nsm = h.nsm
	}
	if q.path == "" {
		q.path = PathCredentials
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := httptest.NewRequest(http.MethodPost, q.path, bytes.NewReader(q.body))
	bh := relayauth.BodyHash(q.body)
	relayauth.SetHeaders(r.Header, priv, http.MethodPost, q.path, q.signAt, bh)
	digest := relayauth.Digest(http.MethodPost, q.path, r.Header.Get("X-VettID-Timestamp"), bh)
	if q.attestDigest != nil {
		digest = *q.attestDigest
	}
	key := pub
	if q.attestKey != nil {
		key = q.attestKey
	}
	if !q.noAttest {
		r.Header.Set(HeaderAttestation, nsmtest.Header(q.nsm.AttestAt(q.attestAt, digest[:], nil, key)))
	}
	return r
}

func (h *harness) do(r *http.Request) (int, []byte) {
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

func code(body []byte) string {
	var e errorBody
	_ = json.Unmarshal(body, &e)
	return e.Code
}

func (h *harness) expect(name string, r *http.Request, status int, errCode string) []byte {
	h.t.Helper()
	st, body := h.do(r)
	if st != status || (errCode != "" && code(body) != errCode) {
		h.t.Fatalf("%s: %d %s, want %d %s", name, st, body, status, errCode)
	}
	return body
}

// A valid request: 200 with count credentials that coturn would accept
// under the current secret, and the URLs of §5.2.
func TestValid(t *testing.T) {
	h := newHarness(t, nil)
	for _, n := range []int{1, 2, 3, 4} {
		body := h.expect("valid", h.request(req{body: []byte(`{"count":` + string(rune('0'+n)) + `}`)}), 200, "")
		var a Answer
		if err := json.Unmarshal(body, &a); err != nil {
			t.Fatal(err)
		}
		if strings.Join(a.STUN, ",") != "stun:turn.staging.vettid.org:3478" ||
			strings.Join(a.TURN, ",") != "turn:turn.staging.vettid.org:3478?transport=udp,turn:turn.staging.vettid.org:3478?transport=tcp" {
			t.Fatalf("urls %+v", a)
		}
		if len(a.Credentials) != n {
			t.Fatalf("%d credentials for count %d", len(a.Credentials), n)
		}
		for _, c := range a.Credentials {
			if c.Exp != t0.Add(6*time.Hour).Unix() {
				t.Fatalf("exp %d", c.Exp)
			}
			if !turncred.Check([]string{secB}, c.Username, c.Credential, t0) {
				t.Fatal("not signed with the current secret")
			}
			if turncred.Check([]string{secA}, c.Username, c.Credential, t0) {
				t.Fatal("signed with a secret that is not current")
			}
		}
	}
	if got := h.reg.Value("requests", dim("outcome", "ok")); got != 4 {
		t.Fatalf("requests{ok} = %v", got)
	}
	// Deprecated releases are admitted too (§5.2 step 2).
	h.nsm.PCRs[0] = nsmtest.PCR(0xb0)
	h.expect("deprecated release", h.request(req{}), 200, "")
}

// Expired: a stale signature is 401 before the attestation is looked at;
// a stale document is 403.
func TestExpired(t *testing.T) {
	h := newHarness(t, nil)
	h.expect("signature 91 s old", h.request(req{signAt: t0.Add(-91 * time.Second)}), 401, CodeTimestampStale)
	h.expect("signature 91 s ahead", h.request(req{signAt: t0.Add(91 * time.Second)}), 401, CodeTimestampStale)
	h.expect("signature 89 s old", h.request(req{signAt: t0.Add(-89 * time.Second)}), 200, "")
	h.expect("document 301 s old", h.request(req{attestAt: t0.Add(-301 * time.Second)}), 403, CodeAttestationInvalid)
	h.expect("document 301 s ahead", h.request(req{attestAt: t0.Add(301 * time.Second)}), 403, CodeAttestationInvalid)
	if h.reg.Value("attestation_failures", dim("reason", "stale")) != 2 {
		t.Fatal("attestation_failures{stale}")
	}
}

// Wrong measurement: a PCR0 that is not an active or deprecated release.
func TestWrongMeasurement(t *testing.T) {
	h := newHarness(t, nil)
	for _, c := range []struct {
		name string
		pcr  byte
	}{{"unknown release", 0xee}, {"retired release", 0xc0}, {"removed release", 0xd0}} {
		h.nsm.PCRs[0] = nsmtest.PCR(c.pcr)
		h.expect(c.name, h.request(req{}), 403, CodeAttestationInvalid)
	}
	if h.reg.Value("attestation_failures", dim("reason", "pcr0")) != 3 {
		t.Fatal("attestation_failures{pcr0}")
	}
	// Another PKI with the right PCRs: the chain does not end at the root.
	stranger := nsmtest.New(0xa0, h.clk.Now)
	h.expect("another root", h.request(req{nsm: stranger}), 403, CodeAttestationInvalid)
	// The document binds another key, or another request.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	h.expect("public_key of another key", h.request(req{attestKey: other}), 403, CodeAttestationInvalid)
	d := relayauth.BodyHash([]byte("another request"))
	h.expect("user_data of another request", h.request(req{attestDigest: &d}), 403, CodeAttestationInvalid)
	h.expect("no attestation", h.request(req{noAttest: true}), 403, CodeAttestationInvalid)
	for _, r := range []string{"chain", "public_key", "user_data", "missing"} {
		if h.reg.Value("attestation_failures", dim("reason", r)) != 1 {
			t.Fatalf("attestation_failures{%s}", r)
		}
	}
}

// Wrong manifest: unsigned by the pinned key, rolled back, or older than
// 7 days by the wall clock.
func TestWrongManifest(t *testing.T) {
	// Signed by a key that is not pinned: no manifest is ever trusted.
	h := newHarness(t, nil)
	h.signer = nsmtest.NewManifestSigner()
	h.serve(5, nsmtest.Release(12, h.nsm.PCR0Hex(), manifest.StatusActive))
	h.expect("unpinned manifest key", h.request(req{}), 403, CodeAttestationInvalid)
	if h.reg.Value("attestation_failures", dim("reason", "no_manifest")) != 1 {
		t.Fatal("attestation_failures{no_manifest}")
	}

	// A rollback is refused; the trusted manifest stays.
	h = newHarness(t, nil)
	h.expect("first", h.request(req{}), 200, "")
	h.serve(4) // a lower serial that would remove every release
	h.clk.Set(t0.Add(11 * time.Minute))
	h.expect("after a rollback", h.request(req{}), 200, "")
	if h.m.Serial() != 5 {
		t.Fatalf("serial %d", h.m.Serial())
	}

	// A new serial that withdraws the release takes effect at the next
	// attempt: a minute after the failed one (the rollback did not renew
	// the manifest), not before.
	h.serve(6, nsmtest.Release(12, h.nsm.PCR0Hex(), manifest.StatusRetired),
		nsmtest.Release(13, nsmtest.PCRHex(0xf0), manifest.StatusActive))
	h.clk.Set(t0.Add(11*time.Minute + 30*time.Second))
	h.expect("before the next attempt", h.request(req{}), 200, "")
	h.clk.Set(t0.Add(12 * time.Minute))
	h.expect("after the refresh", h.request(req{}), 403, CodeAttestationInvalid)
	if h.m.Serial() != 6 {
		t.Fatalf("serial %d", h.m.Serial())
	}

	// The manifest site goes away: trusted for 7 days from the last
	// successful refresh, by the wall clock, then refused.
	h = newHarness(t, nil)
	h.expect("first", h.request(req{}), 200, "")
	h.site.Close()
	h.clk.Set(t0.Add(7*24*time.Hour - time.Minute))
	h.expect("6 days 23:59 later", h.request(req{}), 200, "")
	h.clk.Set(t0.Add(7 * 24 * time.Hour))
	h.expect("7 days later", h.request(req{}), 403, CodeAttestationInvalid)
	if h.reg.Value("attestation_failures", dim("reason", "manifest_stale")) != 1 {
		t.Fatal("attestation_failures{manifest_stale}")
	}
}

// The manifest is fetched once per 10 minutes, not per request, and a
// failing site is retried at most once a minute.
func TestManifestRefreshCadence(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i < 5; i++ {
		h.expect("valid", h.request(req{}), 200, "")
	}
	if h.fetches.Load() != 1 {
		t.Fatalf("%d fetches", h.fetches.Load())
	}
	h.clk.Set(t0.Add(9 * time.Minute))
	h.expect("9 min", h.request(req{}), 200, "")
	h.clk.Set(t0.Add(10 * time.Minute))
	h.expect("10 min", h.request(req{}), 200, "")
	if h.fetches.Load() != 2 {
		t.Fatalf("%d fetches", h.fetches.Load())
	}
}

// Replay: the issuer keeps no replay cache (§5.2), so a request replayed
// within the 90 s window is answered again, with other credentials; past
// the window it is stale.
func TestReplay(t *testing.T) {
	h := newHarness(t, nil)
	r := h.request(req{})
	body, _ := io.ReadAll(r.Body)
	again := func() *http.Request {
		c := httptest.NewRequest(http.MethodPost, PathCredentials, bytes.NewReader(body))
		c.Header = r.Header.Clone()
		return c
	}
	var a, b Answer
	_ = json.Unmarshal(h.expect("first", again(), 200, ""), &a)
	h.clk.Set(t0.Add(89 * time.Second))
	_ = json.Unmarshal(h.expect("replayed within the window", again(), 200, ""), &b)
	if a.Credentials[0].Username == b.Credentials[0].Username {
		t.Fatal("a replay yields the same username")
	}
	h.clk.Set(t0.Add(91 * time.Second))
	h.expect("replayed after the window", again(), 401, CodeTimestampStale)
	// Altering the replayed body breaks the signature.
	c := httptest.NewRequest(http.MethodPost, PathCredentials, strings.NewReader(`{"count":3}`))
	c.Header = r.Header.Clone()
	h.clk.Set(t0)
	h.expect("altered body", c, 401, CodeSignatureInvalid)
}

func TestSignature(t *testing.T) {
	h := newHarness(t, nil)
	r := h.request(req{})
	r.Header.Del("X-VettID-Sig")
	h.expect("no signature", r, 401, CodeSignatureInvalid)
	r = h.request(req{})
	r.Header.Set("X-VettID-Key", "AAAA")
	h.expect("bad key", r, 401, CodeSignatureInvalid)
	// The signature covers the path.
	r = h.request(req{path: "/v1/other"})
	r.URL.Path = PathCredentials
	h.expect("signed for another path", r, 401, CodeSignatureInvalid)
	if h.reg.Value("attestation_failures", dim("reason", "missing")) != 0 {
		t.Fatal("the attestation was looked at before the signature")
	}
}

// The body (step 3), only after the attestation.
func TestBody(t *testing.T) {
	h := newHarness(t, nil)
	for _, b := range []string{`{"count":0}`, `{"count":5}`, `{"count":-1}`, `{"count":"1"}`, `{"count":1.5}`,
		`{"count":1e0}`, `{}`, `{"count":null}`, `{"count":1,"x":2}`, `{"count":1} {}`, `[1]`, ``, `{"count":1}x`} {
		h.expect(b, h.request(req{body: []byte(b)}), 400, CodeBadRequest)
	}
	h.expect("over 1 KiB", h.request(req{body: []byte(`{"count":1}` + strings.Repeat(" ", 1100))}), 400, CodeBadRequest)
	h.expect("whitespace is allowed", h.request(req{body: []byte(" {\"count\" : 2}\n")}), 200, "")
	// An unattested request with a bad body is refused for its attestation.
	h.expect("unattested bad body", h.request(req{body: []byte(`{"count":9}`), noAttest: true}), 403, CodeAttestationInvalid)
}

// §7.5: at most MaxInFlight at once; more are answered 429.
func TestInFlight(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	h := newHarness(t, func(c *Config) {
		c.MaxInFlight = 1
		c.Secrets = &secretsrc.Holder{Source: blocking{gate, entered}}
	})
	done := make(chan int)
	first := h.request(req{})
	go func() { st, _ := h.do(first); done <- st }()
	<-entered
	st, body := h.do(h.request(req{}))
	if st != 429 || code(body) != CodeRateLimited {
		t.Fatalf("%d %s", st, body)
	}
	close(gate)
	if st := <-done; st != 200 {
		t.Fatalf("first: %d", st)
	}
	h.expect("after", h.request(req{}), 200, "")
	if h.reg.Value("requests", dim("outcome", CodeRateLimited)) != 1 {
		t.Fatal("requests{rate_limited}")
	}
}

type blocking struct {
	gate    chan struct{}
	entered chan struct{}
}

func (b blocking) Get(context.Context) ([]byte, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.gate
	return []byte(secDoc), nil
}

func TestNoSecret(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Secrets = &secretsrc.Holder{Source: secretsrc.Static(`{}`)} })
	h.expect("no secret", h.request(req{}), 500, CodeInternal)
	if h.reg.Value("internal_errors") != 1 {
		t.Fatal("internal_errors")
	}
	if !strings.Contains(h.logs.String(), "no TURN secret") {
		t.Fatal("not logged")
	}
}

func TestHealthAndRoutes(t *testing.T) {
	h := newHarness(t, nil)
	st, body := h.do(httptest.NewRequest(http.MethodGet, PathHealth, nil))
	if st != 200 || strings.TrimSpace(string(body)) != "{}" {
		t.Fatalf("%d %s", st, body)
	}
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, PathCredentials, nil),
		httptest.NewRequest(http.MethodPost, PathHealth, nil),
		httptest.NewRequest(http.MethodGet, "/", nil),
	} {
		h.expect(r.Method+" "+r.URL.Path, r, 404, CodeNotFound)
	}
}

// §10: nothing of a request reaches the log, and every metric dimension
// is from a closed set.
func TestNothingIdentifyingIsLogged(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Secrets = &secretsrc.Holder{Source: secretsrc.Static(`{}`)} })
	r := h.request(req{})
	key, att := r.Header.Get("X-VettID-Key"), r.Header.Get(HeaderAttestation)
	h.do(r)
	h.do(h.request(req{attestAt: t0.Add(-time.Hour)}))
	logs := h.logs.String()
	for _, s := range []string{key, att[:40], "192.0.2.1", secA, secB} {
		if strings.Contains(logs, s) {
			t.Fatalf("the log holds %q", s)
		}
	}
	_, data := h.reg.Take()
	allowed := map[string]bool{}
	for _, o := range Outcomes {
		allowed[o] = true
	}
	for _, r := range attest.Reasons {
		allowed[string(r)] = true
	}
	for _, d := range data {
		for _, dm := range d.Dims {
			if !allowed[dm.Value] {
				t.Fatalf("dimension %s=%s", dm.Name, dm.Value)
			}
		}
	}
}

func TestConfig(t *testing.T) {
	base := func() Config {
		return Config{Attest: &attest.Verifier{}, Secrets: &secretsrc.Holder{}, TURNHost: "turn.example.org"}
	}
	for name, mut := range map[string]func(*Config){
		"no verifier":    func(c *Config) { c.Attest = nil },
		"no secrets":     func(c *Config) { c.Secrets = nil },
		"host with port": func(c *Config) { c.TURNHost = "turn.example.org:3478" },
		"upper case":     func(c *Config) { c.TURNHost = "TURN.example.org" },
		"empty host":     func(c *Config) { c.TURNHost = "" },
		"7 h lifetime":   func(c *Config) { c.Lifetime = 7 * time.Hour },
	} {
		c := base()
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

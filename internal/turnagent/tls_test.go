package turnagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/tlscert"
	"github.com/vettid/vettid-calls/internal/tlscert/certtest"
	"github.com/vettid/vettid-calls/internal/turncred"
	"github.com/vettid/vettid-calls/internal/turnsstatus"
)

const realm = "turn.staging.vettid.org"

// certSource is a settable certificate secret.
type certSource struct {
	mu  sync.Mutex
	doc []byte
	err error
}

func (s *certSource) Get(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc, s.err
}
func (s *certSource) set(doc []byte, err error) { s.mu.Lock(); s.doc, s.err = doc, err; s.mu.Unlock() }

// putter records the statuses put.
type putter struct {
	puts []turnsstatus.Status
	err  error
}

func (p *putter) Put(_ context.Context, b []byte) error {
	if p.err != nil {
		return p.err
	}
	s, err := turnsstatus.Parse(b)
	if err != nil {
		return err
	}
	p.puts = append(p.puts, s)
	return nil
}

// sigProc is a coturn that only records signals.
type sigProc struct{ sigs []os.Signal }

func (p *sigProc) Wait() error              { select {} }
func (p *sigProc) Signal(s os.Signal) error { p.sigs = append(p.sigs, s); return nil }

type tlsHarness struct {
	t     *testing.T
	ca    *certtest.CA
	src   *certSource
	put   *putter
	now   time.Time
	serve map[string]*x509.Certificate // by address; nil entry: the handshake fails
	dials []string
	a     *Agent
}

func newTLSHarness(t *testing.T) *tlsHarness {
	h := &tlsHarness{t: t, ca: certtest.NewCA(time.Time{}, time.Time{}), src: &certSource{}, put: &putter{},
		now: time.Now().Round(0), serve: map[string]*x509.Certificate{}}
	p := params()
	p.RunDir, p.Secrets = t.TempDir(), nil
	h.a = &Agent{Params: p, Metrics: metrics.New("test", nil), TLS: &TLS{
		Source: h.src, Status: h.put, Roots: h.ca.Roots(), Now: func() time.Time { return h.now },
		Dial: func(_ context.Context, addr string, cfg *tls.Config) (*x509.Certificate, error) {
			if cfg.ServerName != realm || cfg.RootCAs == nil || cfg.MinVersion != tls.VersionTLS12 {
				t.Errorf("probe config %+v", cfg)
			}
			h.dials = append(h.dials, addr)
			c, ok := h.serve[addr]
			if !ok || c == nil {
				return nil, errors.New("refused")
			}
			return c, nil
		}}}
	return h
}

const (
	v4 = "10.40.0.12:443"
	v6 = "[2600:1f18:1234:5600::20]:443"
)

func (h *tlsHarness) serveLeaf(c *x509.Certificate) { h.serve[v4], h.serve[v6] = c, c }
func (h *tlsHarness) count(name, kind string) float64 {
	return h.a.Metrics.Value(name, metrics.Dim{Name: "kind", Value: kind})
}

// A valid certificate is used and written re-encoded; coturn is
// probed on both addresses and the status put, then every 10 minutes.
func TestTLSServe(t *testing.T) {
	h := newTLSHarness(t)
	l := h.ca.Leaf(realm, certtest.Opts{})
	h.src.set(l.Doc(), nil)
	h.a.tlsLoad(context.Background(), false)
	files := h.a.tlsFiles()
	if files == nil {
		t.Fatal("no certificate in use")
	}
	key, err := os.ReadFile(files.Key)
	if err != nil || !strings.Contains(string(key), "BEGIN PRIVATE KEY") {
		t.Fatal("key file", err)
	}
	if runtime.GOOS != "windows" {
		for _, f := range []string{files.Key, files.Chain} {
			if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v", f, st.Mode().Perm())
			}
		}
	}
	cur := &running{proc: &sigProc{}, tls: true, promUp: true}
	h.serveLeaf(l.Cert)
	if r := h.a.tlsStep(context.Background(), cur); r != "" {
		t.Fatal(r)
	}
	if strings.Join(h.dials, ",") != v4+","+v6 {
		t.Fatalf("dials %v", h.dials)
	}
	if h.a.Metrics.Value("tls") != 1 || len(h.put.puts) != 1 || h.put.puts[0].VerifiedAt != h.now.Unix() ||
		h.put.puts[0].NotAfter != l.Cert.NotAfter.Unix() {
		t.Fatalf("tls %v puts %+v", h.a.Metrics.Value("tls"), h.put.puts)
	}
	if v := h.a.Metrics.Value("tls_served_life_left"); v < 98 || v > 100 {
		t.Fatal("life left", v)
	}
	h.now = h.now.Add(5 * time.Minute)
	h.a.tlsStep(context.Background(), cur)
	if len(h.put.puts) != 1 {
		t.Fatal("status put again within 10 minutes")
	}
	h.now = h.now.Add(5 * time.Minute)
	h.a.tlsStep(context.Background(), cur)
	if len(h.put.puts) != 2 {
		t.Fatal("status not refreshed after 10 minutes")
	}
}

// One failed handshake (on either address) writes nothing and drops tls
// to 0; a failed put is tls_status and is tried again.
func TestTLSProbeFailure(t *testing.T) {
	h := newTLSHarness(t)
	l := h.ca.Leaf(realm, certtest.Opts{})
	h.src.set(l.Doc(), nil)
	h.a.tlsLoad(context.Background(), false)
	cur := &running{proc: &sigProc{}, tls: true, promUp: true}
	h.serveLeaf(l.Cert)
	h.a.tlsStep(context.Background(), cur)
	h.serve[v6] = nil
	h.now = h.now.Add(time.Minute)
	if r := h.a.tlsStep(context.Background(), cur); r != "" {
		t.Fatal(r)
	}
	if h.a.Metrics.Value("tls") != 0 || len(h.put.puts) != 1 || h.count("agent_errors", "tls_probe") != 1 {
		t.Fatalf("tls %v puts %d", h.a.Metrics.Value("tls"), len(h.put.puts))
	}
	// Another certificate served: not verified either.
	h.serveLeaf(h.ca.Leaf(realm, certtest.Opts{}).Cert)
	h.now = h.now.Add(time.Minute)
	h.a.tlsStep(context.Background(), cur)
	if h.a.Metrics.Value("tls") != 0 || len(h.put.puts) != 1 {
		t.Fatal("another certificate verified")
	}
	// Back; the put fails, then succeeds.
	h.serveLeaf(l.Cert)
	h.put.err = errors.New("denied")
	h.now = h.now.Add(20 * time.Minute)
	h.a.tlsStep(context.Background(), cur)
	if h.count("agent_errors", "tls_status") != 1 {
		t.Fatal("tls_status not counted")
	}
	h.put.err = nil
	h.now = h.now.Add(time.Minute)
	h.a.tlsStep(context.Background(), cur)
	if len(h.put.puts) != 2 {
		t.Fatal("put not tried again")
	}
}

// A failed read keeps the certificate in use; an empty or invalid value,
// or the certificate's end, takes TLS off (a restart), and the zero
// status is put at once.
func TestTLSKeepAndDrop(t *testing.T) {
	h := newTLSHarness(t)
	l := h.ca.Leaf(realm, certtest.Opts{})
	h.src.set(l.Doc(), nil)
	h.a.tlsLoad(context.Background(), false)
	cur := &running{proc: &sigProc{}, tls: true, promUp: true}
	h.serveLeaf(l.Cert)
	h.a.tlsStep(context.Background(), cur)

	h.src.set(nil, errors.New("network"))
	h.now = h.now.Add(11 * time.Minute)
	if r := h.a.tlsStep(context.Background(), cur); r != "" || h.a.tlsFiles() == nil || h.count("agent_errors", "tls_read") != 1 {
		t.Fatal("a failed read dropped TLS", r)
	}
	for name, doc := range map[string][]byte{
		"empty":      []byte(`{}`),
		"other name": h.ca.Leaf("turn.example.org", certtest.Opts{}).Doc(),
		"malformed":  []byte(`{"key":"x"}`),
	} {
		h.src.set(l.Doc(), nil)
		h.now = h.now.Add(11 * time.Minute)
		h.a.tlsStep(context.Background(), cur)
		if h.a.tlsFiles() == nil {
			t.Fatal("good again")
		}
		h.src.set(doc, nil)
		h.now = h.now.Add(11 * time.Minute)
		if r := h.a.tlsStep(context.Background(), cur); r != "tls" || h.a.tlsFiles() != nil {
			t.Fatalf("%s: %q", name, r)
		}
		// Restarted without TLS: the zero status at once, then nothing more.
		off := &running{proc: &sigProc{}, tls: false}
		n := len(h.put.puts)
		h.a.tlsStep(context.Background(), off)
		if len(h.put.puts) != n+1 || h.put.puts[n] != (turnsstatus.Status{}) || h.a.Metrics.Value("tls") != 0 {
			t.Fatalf("%s: zero status %+v", name, h.put.puts)
		}
		h.a.tlsStep(context.Background(), off)
		if len(h.put.puts) != n+1 {
			t.Fatalf("%s: zero status put twice", name)
		}
		h.a.TLS.published = true // as before the next round
	}
	if h.count("agent_errors", "tls_invalid") != 3 {
		t.Fatal("tls_invalid", h.count("agent_errors", "tls_invalid"))
	}

	// The end: on time, not at the next read.
	short := h.ca.Leaf(realm, certtest.Opts{NotAfter: h.now.Add(2 * time.Hour)})
	h.src.set(short.Doc(), nil)
	h.now = h.now.Add(11 * time.Minute)
	h.a.tlsStep(context.Background(), &running{proc: &sigProc{}, tls: false})
	if h.a.tlsFiles() == nil {
		t.Fatal("short certificate not used")
	}
	h.now = short.Cert.NotAfter.Add(time.Second)
	h.a.TLS.loaded = h.now // no read due
	if r := h.a.tlsStep(context.Background(), &running{proc: &sigProc{}, tls: true, promUp: true}); r != "tls" {
		t.Fatal("not taken off at the end", r)
	}
}

// A renewed certificate: written, SIGUSR2 only once coturn answers, the
// old leaf accepted at the first handshake after it, a restart when the
// reload never takes.
func TestTLSReload(t *testing.T) {
	h := newTLSHarness(t)
	old := h.ca.Leaf(realm, certtest.Opts{})
	h.src.set(old.Doc(), nil)
	h.a.tlsLoad(context.Background(), false)
	proc := &sigProc{}
	cur := &running{proc: proc, tls: true}
	h.serveLeaf(old.Cert)
	h.a.tlsStep(context.Background(), cur)

	renewed := h.ca.Leaf(realm, certtest.Opts{})
	h.src.set(renewed.Doc(), nil)
	h.now = h.now.Add(11 * time.Minute)
	h.a.tlsStep(context.Background(), cur) // promUp false: no signal yet
	if len(proc.sigs) != 0 {
		t.Fatal("SIGUSR2 before coturn answered")
	}
	chain, _ := os.ReadFile(h.a.tlsFiles().Chain)
	d, err := tlscert.Parse(mustDoc(h.a.tlsFiles()))
	if err != nil || !d.Leaf().Equal(renewed.Cert) || !strings.Contains(string(chain), "BEGIN CERTIFICATE") {
		t.Fatal("renewed files not written", err)
	}
	cur.promUp = true
	h.now = h.now.Add(time.Minute)
	if r := h.a.tlsStep(context.Background(), cur); r != "" || len(proc.sigs) != 1 || proc.sigs[0] != reloadSignal {
		t.Fatalf("signal %v, %q", proc.sigs, r)
	}
	if h.a.Metrics.Value("tls") != 1 {
		t.Fatal("the old leaf was not accepted at the first handshake after SIGUSR2")
	}
	// Still the old leaf: not verified from now on, and a restart after 10 minutes.
	h.now = h.now.Add(time.Minute)
	if r := h.a.tlsStep(context.Background(), cur); r != "" || h.a.Metrics.Value("tls") != 0 {
		t.Fatal("old leaf verified twice", r)
	}
	h.now = h.now.Add(9 * time.Minute)
	if r := h.a.tlsStep(context.Background(), cur); r != "tls_reload" {
		t.Fatalf("no restart for a reload that did not take: %q", r)
	}

	// A reload that takes: no restart.
	h2 := newTLSHarness(t)
	a, b := h2.ca.Leaf(realm, certtest.Opts{}), h2.ca.Leaf(realm, certtest.Opts{})
	h2.src.set(a.Doc(), nil)
	h2.a.tlsLoad(context.Background(), false)
	cur2 := &running{proc: &sigProc{}, tls: true, promUp: true}
	h2.serveLeaf(a.Cert)
	h2.a.tlsStep(context.Background(), cur2)
	h2.src.set(b.Doc(), nil)
	h2.now = h2.now.Add(11 * time.Minute)
	h2.serveLeaf(b.Cert)
	h2.a.tlsStep(context.Background(), cur2)
	h2.now = h2.now.Add(20 * time.Minute)
	if r := h2.a.tlsStep(context.Background(), cur2); r != "" || h2.a.Metrics.Value("tls") != 1 {
		t.Fatal("a reload that took", r)
	}
}

// With no certificate, coturn runs without TLS; one arriving switches it
// on (a restart).
func TestTLSSwitchOn(t *testing.T) {
	h := newTLSHarness(t)
	h.src.set(nil, secretsrc.ErrNotFound)
	h.a.tlsLoad(context.Background(), false)
	if h.a.tlsFiles() != nil {
		t.Fatal("TLS without a certificate")
	}
	off := &running{proc: &sigProc{}, tls: false}
	if r := h.a.tlsStep(context.Background(), off); r != "" || len(h.put.puts) != 0 {
		t.Fatal("off", r, h.put.puts)
	}
	h.src.set(h.ca.Leaf(realm, certtest.Opts{}).Doc(), nil)
	h.now = h.now.Add(11 * time.Minute)
	if r := h.a.tlsStep(context.Background(), off); r != "tls" {
		t.Fatalf("not switched on: %q", r)
	}
	// Rendered with the TLS lines.
	set := mustSet(t)
	conf, err := h.a.writeConf(set)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(conf)
	if !strings.Contains(string(b), "tls-listening-port=443") || !strings.Contains(string(b), "pkey="+filepath.Join(h.a.Params.RunDir, TLSKeyName)) {
		t.Fatalf("not rendered with TLS:\n%s", b)
	}
}

func mustDoc(f *TLSFiles) []byte {
	key, _ := os.ReadFile(f.Key)
	chain, _ := os.ReadFile(f.Chain)
	return []byte(`{"key":` + quote(string(key)) + `,"chain":` + quote(string(chain)) + `}`)
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

func mustSet(t *testing.T) *turncred.Set {
	t.Helper()
	h := &secretsrc.Holder{Source: secretsrc.Static(`{"current":"a","secrets":{"a":"` + secA + `"}}`)}
	s := h.Get(context.Background())
	if s == nil {
		t.Fatal("no set")
	}
	return s
}

// Through Run: coturn starts with TLS when a certificate is valid at
// start, and is restarted without it when the certificate goes.
func TestAgentRunTLS(t *testing.T) {
	h := newTLSHarness(t)
	l := h.ca.Leaf(realm, certtest.Opts{})
	h.src.set(l.Doc(), nil)
	h.serveLeaf(l.Cert)
	var mu sync.Mutex
	clock := h.now
	h.a.TLS.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	confs := make(chan string, 10)
	h.a.Secrets = &secretsrc.Holder{Source: secretsrc.Static(`{"current":"a","secrets":{"a":"` + secA + `"}}`),
		Now: h.a.TLS.Now}
	rec := &metrics.Recorder{}
	h.a.Sink = rec
	h.a.Start = func(conf string, _ io.Writer) (Process, error) {
		b, err := os.ReadFile(conf)
		if err != nil {
			return nil, err
		}
		confs <- string(b)
		return &fakeProc{done: make(chan struct{})}, nil
	}
	h.a.Scrape = func(context.Context) (Scrape, error) { return ParseExposition(strings.NewReader(exposition)) }
	h.a.Interval, h.a.RestartDelay, h.a.StopTimeout = 10*time.Millisecond, time.Millisecond, time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- h.a.Run(ctx) }()
	if c := <-confs; !strings.Contains(c, "tls-listening-port=443") || strings.Contains(c, "no-tls") {
		t.Fatalf("first start without TLS:\n%s", c)
	}
	h.src.set([]byte(`{}`), nil)
	mu.Lock()
	clock = clock.Add(11 * time.Minute)
	mu.Unlock()
	select {
	case c := <-confs:
		if strings.Contains(c, "tls-listening-port") || !strings.Contains(c, "no-tls") {
			t.Fatalf("restarted with TLS:\n%s", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not restarted without TLS")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	restarts := 0.0
	for _, batch := range rec.Data {
		for _, d := range batch {
			if d.Name == "coturn_restarts" && len(d.Dims) == 1 && d.Dims[0].Value == "tls" {
				restarts += d.Value
			}
		}
	}
	if restarts < 1 {
		t.Fatal("coturn_restarts{tls}")
	}
}

// The real handshake: the served leaf, verified for the name against the
// roots; another name or other roots fail.
func TestDialLeaf(t *testing.T) {
	ca := certtest.NewCA(time.Time{}, time.Time{})
	l := ca.Leaf(realm, certtest.Opts{})
	cert := tls.Certificate{Certificate: [][]byte{l.Cert.Raw, ca.Inter.Raw}, PrivateKey: l.Key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	ctx := context.Background()
	leaf, err := dialLeaf(ctx, ln.Addr().String(), &tls.Config{ServerName: realm, RootCAs: ca.Roots(), MinVersion: tls.VersionTLS12})
	if err != nil || !leaf.Equal(l.Cert) {
		t.Fatal("served leaf", err)
	}
	if _, err := dialLeaf(ctx, ln.Addr().String(), &tls.Config{ServerName: "turn.example.org", RootCAs: ca.Roots()}); err == nil {
		t.Fatal("another name verified")
	}
	other := certtest.NewCA(time.Time{}, time.Time{})
	if _, err := dialLeaf(ctx, ln.Addr().String(), &tls.Config{ServerName: realm, RootCAs: other.Roots()}); err == nil {
		t.Fatal("other roots verified")
	}
}

// A coturn started after new files were written reads them itself: no
// SIGUSR2 and no reload wait carry over to it.
func TestTLSStartClearsReload(t *testing.T) {
	h := newTLSHarness(t)
	a, b := h.ca.Leaf(realm, certtest.Opts{}), h.ca.Leaf(realm, certtest.Opts{})
	h.src.set(a.Doc(), nil)
	h.a.tlsLoad(context.Background(), false)
	h.src.set(b.Doc(), nil)
	h.now = h.now.Add(11 * time.Minute)
	h.a.tlsLoad(context.Background(), true)
	if !h.a.TLS.pending {
		t.Fatal("not pending")
	}
	h.a.Start = func(string, io.Writer) (Process, error) { return &sigProc{}, nil }
	r, err := h.a.start("conf")
	if err != nil {
		t.Fatal(err)
	}
	if h.a.TLS.pending || h.a.TLS.prevLeaf != nil || !r.tls {
		t.Fatal("a reload carried over to a new coturn")
	}
}

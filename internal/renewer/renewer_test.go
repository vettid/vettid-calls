package renewer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/tlscert"
	"github.com/vettid/vettid-calls/internal/tlscert/certtest"
)

const name = "turn.staging.vettid.org"

// fakeCA is the ACME side: a test CA, one account.
type fakeCA struct {
	ca        *certtest.CA
	url       string
	regs      int
	orders    int
	accepted  int
	revoked   [][]byte
	failAt    string // a method name that fails
	lifetime  time.Duration
	rolled    crypto.Signer
	lastKey   crypto.Signer
	challenge string
}

func (f *fakeCA) client(key crypto.Signer, url string) ACME {
	f.lastKey = key
	return &fakeClient{f: f, key: key, url: url}
}

type fakeClient struct {
	f   *fakeCA
	key crypto.Signer
	url string
}

func (c *fakeClient) err(m string) error {
	if c.f.failAt == m {
		return errors.New(m + " failed")
	}
	return nil
}
func (c *fakeClient) Register(context.Context) (string, error) {
	c.f.regs++
	return c.f.url, c.err("Register")
}
func (c *fakeClient) Order(_ context.Context, n string) (*Order, error) {
	if n != name {
		return nil, errors.New("wrong name")
	}
	c.f.orders++
	return &Order{URL: "order", Authz: []string{"authz"}}, c.err("Order")
}
func (c *fakeClient) DNSChallenge(context.Context, string) (*Challenge, error) {
	c.f.challenge = "record-value"
	return &Challenge{URL: "chal", Token: "tok", Record: c.f.challenge}, c.err("DNSChallenge")
}
func (c *fakeClient) Accept(context.Context, *Challenge) error {
	c.f.accepted++
	return c.err("Accept")
}
func (c *fakeClient) WaitAuthorization(context.Context, string) error {
	return c.err("WaitAuthorization")
}
func (c *fakeClient) Finalize(_ context.Context, _ string, csr []byte) ([][]byte, error) {
	if err := c.err("Finalize"); err != nil {
		return nil, err
	}
	o := certtest.Opts{}
	if c.f.lifetime != 0 {
		o.NotAfter = time.Now().Add(c.f.lifetime)
	}
	leaf := c.f.ca.SignCSR(csr, o)
	return [][]byte{leaf.Raw, c.f.ca.Inter.Raw}, nil
}
func (c *fakeClient) Revoke(_ context.Context, der []byte) error {
	if err := c.err("Revoke"); err != nil {
		return err
	}
	c.f.revoked = append(c.f.revoked, der)
	return nil
}
func (c *fakeClient) Rollover(_ context.Context, k crypto.Signer) error {
	c.f.rolled = k
	return c.err("Rollover")
}

type fakeDNS struct {
	records map[string]string
	upserts int
	deletes int
	fail    string
}

func (d *fakeDNS) Upsert(_ context.Context, n, v string) (string, error) {
	if d.fail == "Upsert" {
		return "", errors.New("upsert failed")
	}
	d.upserts++
	d.records[n] = v
	return "change", nil
}
func (d *fakeDNS) WaitInSync(context.Context, string) error {
	if d.fail == "WaitInSync" {
		return errors.New("not in sync")
	}
	return nil
}
func (d *fakeDNS) Delete(_ context.Context, n, _ string) error {
	d.deletes++
	delete(d.records, n)
	return nil
}

type fakeSecrets struct {
	m    map[string][]byte
	puts map[string]int
	fail string
}

func (s *fakeSecrets) Get(_ context.Context, id string) ([]byte, error) {
	b, ok := s.m[id]
	if !ok {
		return nil, errors.New("no such secret")
	}
	return b, nil
}
func (s *fakeSecrets) Put(_ context.Context, id string, v []byte) error {
	if s.fail == id {
		return errors.New("put failed")
	}
	s.m[id] = v
	s.puts[id]++
	return nil
}

type harness struct {
	r    *Renewer
	ca   *fakeCA
	dns  *fakeDNS
	sec  *fakeSecrets
	logs *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ca := certtest.NewCA(time.Time{}, time.Time{})
	h := &harness{ca: &fakeCA{ca: ca, url: "https://acme.test/acct/1"}, dns: &fakeDNS{records: map[string]string{}},
		sec: &fakeSecrets{m: map[string][]byte{"cert": []byte(`{}`), "acct": []byte(`{}`)}, puts: map[string]int{}}, logs: &bytes.Buffer{}}
	h.r = &Renewer{Name: name, CertSecret: "cert", AccountSecret: "acct", Secrets: h.sec, DNS: h.dns, ACME: h.ca.client,
		Roots: ca.Roots(), Metrics: metrics.New("test", nil), Log: slog.New(slog.NewTextHandler(h.logs, nil))}
	return h
}

func (h *harness) run(t *testing.T, in Input) Result {
	t.Helper()
	res, err := h.r.Run(context.Background(), in)
	if err != nil {
		t.Fatalf("%s: %v (%+v)", in.Action, err, res)
	}
	return res
}

func (h *harness) cert(t *testing.T) *tlscert.Doc {
	t.Helper()
	d, err := tlscert.Parse(h.sec.m["cert"])
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (h *harness) account(t *testing.T) *Account {
	t.Helper()
	a, err := parseAccount(h.sec.m["acct"])
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRegisterThenRenew(t *testing.T) {
	h := newHarness(t)
	// renew without an account fails at "account".
	if res, err := h.r.Run(context.Background(), Input{Action: ActionRenew}); err == nil || res.Step != "account" {
		t.Fatalf("%+v %v", res, err)
	}
	res := h.run(t, Input{Action: ActionRegister})
	if res.Outcome != OutcomeRegistered || res.AccountURL != h.ca.url || h.ca.regs != 1 {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(h.logs.String(), h.ca.url) {
		t.Fatal("the account URL was not logged")
	}
	// register again: nothing changes.
	if res := h.run(t, Input{Action: ActionRegister}); res.Outcome != OutcomeKept || h.ca.regs != 1 {
		t.Fatalf("%+v", res)
	}
	// renew with no certificate: issues, with DNS-01, and the record goes.
	res = h.run(t, Input{Action: ActionRenew})
	if res.Outcome != OutcomeIssued || h.dns.upserts != 1 || h.dns.deletes != 1 || len(h.dns.records) != 0 || h.ca.accepted != 1 {
		t.Fatalf("%+v %+v", res, h.dns)
	}
	d := h.cert(t)
	if err := d.Verify(name, h.ca.ca.Roots(), time.Now()); err != nil || res.Serial != Serial(d.Leaf()) {
		t.Fatal(err)
	}
	if a := h.account(t); len(a.Issued) != 1 || !a.Issued[0].Equal(d.Leaf()) {
		t.Fatal("the issued certificate is not listed")
	}
	// renew again: kept.
	if res := h.run(t, Input{Action: ActionRenew}); res.Outcome != OutcomeKept || h.ca.orders != 1 {
		t.Fatalf("%+v", res)
	}
	if v := h.r.Metrics.Value("tls_life_left"); v < 98 {
		t.Fatal("tls_life_left", v)
	}
	// No key material anywhere in the log.
	if strings.Contains(h.logs.String(), "PRIVATE") || strings.Contains(h.logs.String(), "MII") {
		t.Fatal("key material logged")
	}
}

// Renewed at a third of the lifetime left; force issues regardless.
func TestRenewAtAThird(t *testing.T) {
	h := newHarness(t)
	h.run(t, Input{Action: ActionRegister})
	h.ca.lifetime = 90 * 24 * time.Hour
	h.run(t, Input{Action: ActionRenew})
	first := h.cert(t).Leaf()
	h.r.Now = func() time.Time { return first.NotAfter.Add(-31 * 24 * time.Hour) }
	if res := h.run(t, Input{Action: ActionRenew}); res.Outcome != OutcomeKept {
		t.Fatalf("renewed with 31 days left: %+v", res)
	}
	h.r.Now = func() time.Time { return first.NotAfter.Add(-29 * 24 * time.Hour) }
	if res := h.run(t, Input{Action: ActionRenew}); res.Outcome != OutcomeIssued {
		t.Fatalf("not renewed with 29 days left: %+v", res)
	}
	h.r.Now = nil
	before := h.ca.orders
	if res := h.run(t, Input{Action: ActionForce}); res.Outcome != OutcomeIssued || h.ca.orders != before+1 {
		t.Fatalf("%+v", res)
	}
}

// The pinned account: a different stored URL fails every action but
// register at "account".
func TestPinnedAccount(t *testing.T) {
	h := newHarness(t)
	h.run(t, Input{Action: ActionRegister})
	h.r.PinnedAccount = "https://acme.test/acct/2"
	for _, a := range []string{ActionRenew, ActionForce, ActionRekey, ActionRevoke, ActionRollover} {
		res, err := h.r.Run(context.Background(), Input{Action: a})
		if err == nil || res.Step != "account" || res.Outcome != OutcomeFailed {
			t.Errorf("%s: %+v %v", a, res, err)
		}
	}
	if res := h.run(t, Input{Action: ActionRegister}); res.Outcome != OutcomeKept {
		t.Fatalf("%+v", res)
	}
	h.r.PinnedAccount = h.ca.url
	h.run(t, Input{Action: ActionRenew})
}

// A failure at any step keeps what is there, deletes the record, and
// names the step.
func TestFailures(t *testing.T) {
	for method, step := range map[string]string{"Order": "order", "DNSChallenge": "challenge", "Accept": "challenge",
		"WaitAuthorization": "challenge", "Finalize": "finalize"} {
		h := newHarness(t)
		h.run(t, Input{Action: ActionRegister})
		before := string(h.sec.m["cert"])
		h.ca.failAt = method
		res, err := h.r.Run(context.Background(), Input{Action: ActionForce})
		if err == nil || res.Step != step || string(h.sec.m["cert"]) != before || len(h.dns.records) != 0 {
			t.Errorf("%s: %+v %v records %v", method, res, err, h.dns.records)
		}
		if h.r.Metrics.Value("renew", metrics.Dim{Name: "outcome", Value: OutcomeFailed}) != 1 {
			t.Errorf("%s: renew{failed}", method)
		}
	}
	for _, f := range []string{"Upsert", "WaitInSync"} {
		h := newHarness(t)
		h.run(t, Input{Action: ActionRegister})
		h.dns.fail = f
		if res, err := h.r.Run(context.Background(), Input{Action: ActionForce}); err == nil || res.Step != "dns" || len(h.dns.records) != 0 {
			t.Errorf("%s: %+v", f, res)
		}
	}
	// A chain that does not verify (another name's CA): not put.
	h := newHarness(t)
	h.run(t, Input{Action: ActionRegister})
	h.r.Roots = certtest.NewCA(time.Time{}, time.Time{}).Roots()
	if res, err := h.r.Run(context.Background(), Input{Action: ActionForce}); err == nil || res.Step != "verify" || string(h.sec.m["cert"]) != `{}` {
		t.Fatalf("%+v", res)
	}
	// The put fails.
	h = newHarness(t)
	h.run(t, Input{Action: ActionRegister})
	h.sec.fail = "cert"
	if res, _ := h.r.Run(context.Background(), Input{Action: ActionForce}); res.Step != "put" {
		t.Fatalf("%+v", res)
	}
	// Unknown action; serials outside revoke.
	if res, _ := h.r.Run(context.Background(), Input{Action: "delete"}); res.Step != "input" {
		t.Fatalf("%+v", res)
	}
	if res, _ := h.r.Run(context.Background(), Input{Action: ActionRenew, Serials: []string{"01"}}); res.Step != "input" {
		t.Fatalf("%+v", res)
	}
}

// rekey: a new certificate first, then every older listed one revoked;
// the current one stays. A failed revoke is retried with revoke, which
// does not touch the replacement.
func TestRekeyAndRevoke(t *testing.T) {
	h := newHarness(t)
	h.run(t, Input{Action: ActionRegister})
	h.run(t, Input{Action: ActionRenew})
	old1 := h.cert(t).Leaf()
	h.run(t, Input{Action: ActionForce}) // a renewal: old1 is still valid and listed
	old2 := h.cert(t).Leaf()
	h.ca.failAt = "Revoke"
	res, err := h.r.Run(context.Background(), Input{Action: ActionRekey})
	if err == nil || res.Step != "revoke" || len(res.NotRevoked) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	cur := h.cert(t).Leaf()
	if cur.Equal(old2) || !strings.Contains(h.logs.String(), "replacing="+Serial(old2)) {
		t.Fatal("rekey did not replace, or did not log the old serial first")
	}
	h.ca.failAt = ""
	res = h.run(t, Input{Action: ActionRevoke})
	if res.Outcome != OutcomeRevoked || len(h.ca.revoked) != 2 {
		t.Fatalf("%+v", res)
	}
	for _, der := range h.ca.revoked {
		if bytes.Equal(der, cur.Raw) {
			t.Fatal("the current certificate was revoked")
		}
	}
	got := map[string]bool{Serial(old1): false, Serial(old2): false}
	for _, s := range res.Revoked {
		got[s] = true
	}
	if !got[Serial(old1)] || !got[Serial(old2)] {
		t.Fatalf("revoked %v", res.Revoked)
	}
	// Nothing left to revoke: kept, not a failure.
	if res := h.run(t, Input{Action: ActionRevoke}); res.Outcome != OutcomeKept {
		t.Fatalf("%+v", res)
	}
	// The current one: refused unless asked, then revoked.
	if res, err := h.r.Run(context.Background(), Input{Action: ActionRevoke, Serials: []string{Serial(cur)}}); err == nil || res.Step != "revoke" {
		t.Fatalf("%+v", res)
	}
	res = h.run(t, Input{Action: ActionRevoke, Serials: []string{Serial(cur)}, Current: true})
	if len(res.Revoked) != 1 || res.Revoked[0] != Serial(cur) {
		t.Fatalf("%+v", res)
	}
	// An unlisted serial: refused.
	if res, _ := h.r.Run(context.Background(), Input{Action: ActionRevoke, Serials: []string{"ff"}}); res.Step != "revoke" {
		t.Fatalf("%+v", res)
	}
}

func TestRollover(t *testing.T) {
	h := newHarness(t)
	h.run(t, Input{Action: ActionRegister})
	before := h.account(t)
	res := h.run(t, Input{Action: ActionRollover})
	after := h.account(t)
	type pub interface{ Equal(crypto.PublicKey) bool }
	if res.Outcome != OutcomeKept || after.URL != before.URL || h.ca.rolled == nil ||
		after.Key.Public().(pub).Equal(before.Key.Public()) || !after.Key.Public().(pub).Equal(h.ca.rolled.Public()) {
		t.Fatal("rollover")
	}
}

// The account document: strict, and ended leaves are dropped.
func TestAccountDocument(t *testing.T) {
	h := newHarness(t)
	h.run(t, Input{Action: ActionRegister})
	a := h.account(t)
	ended := h.ca.ca.Leaf(name, certtest.Opts{NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
	live := h.ca.ca.Leaf(name, certtest.Opts{})
	a.Issued = []*x509.Certificate{ended.Cert, live.Cert}
	b, err := a.marshal(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a2, err := parseAccount(b)
	if err != nil || len(a2.Issued) != 1 || !a2.Issued[0].Equal(live.Cert) || a2.URL != a.URL {
		t.Fatal("round trip", err)
	}
	for _, bad := range []string{``, `null`, `[]`, `{"key":"x","url":"u","issued":[]}`, `{"url":"u"}`,
		strings.Replace(string(b), `"url"`, `"x":1,"url"`, 1)} {
		if _, err := parseAccount([]byte(bad)); err == nil || errors.Is(err, errEmptyAccount) {
			t.Errorf("accepted %.40q", bad)
		}
	}
	if _, err := parseAccount([]byte(` { } `)); !errors.Is(err, errEmptyAccount) {
		t.Fatal("{} is not empty")
	}
}

package tlscert

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-calls/internal/tlscert/certtest"
)

const name = "turn.staging.vettid.org"

func TestValid(t *testing.T) {
	ca := certtest.NewCA(time.Time{}, time.Time{})
	l := ca.Leaf(name, certtest.Opts{})
	d, err := Parse(l.Doc())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Verify(name, ca.Roots(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if !d.Leaf().Equal(l.Cert) || len(d.Chain) != 2 {
		t.Fatal("chain")
	}
	// Re-encoded, it parses to the same document.
	b, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Parse(b)
	if err != nil || !Same(d, d2) {
		t.Fatal("re-encoded", err)
	}
}

func TestNotValid(t *testing.T) {
	now := time.Now()
	ca := certtest.NewCA(time.Time{}, time.Time{})
	other := certtest.NewCA(time.Time{}, time.Time{})
	expiredInter := certtest.NewCA(now.AddDate(-1, 0, 0), now.Add(-time.Hour))
	good := ca.Leaf(name, certtest.Opts{})
	cases := map[string]struct {
		doc   []byte
		roots *x509.CertPool
	}{
		"other name":         {ca.Leaf("turn.example.org", certtest.Opts{}).Doc(), ca.Roots()},
		"other root":         {good.Doc(), other.Roots()},
		"ended":              {ca.Leaf(name, certtest.Opts{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)}).Doc(), ca.Roots()},
		"not yet":            {ca.Leaf(name, certtest.Opts{NotBefore: now.Add(time.Hour)}).Doc(), ca.Roots()},
		"client auth":        {ca.Leaf(name, certtest.Opts{Usage: x509.ExtKeyUsageClientAuth}).Doc(), ca.Roots()},
		"intermediate ended": {expiredInter.Leaf(name, certtest.Opts{}).Doc(), expiredInter.Roots()},
		"another key": {func() []byte {
			b, _ := json.Marshal(map[string]string{"key": string(ca.Leaf(name, certtest.Opts{}).KeyPEM()), "chain": string(good.ChainPEM())})
			return b
		}(), ca.Roots()},
	}
	for n, c := range cases {
		d, err := Parse(c.doc)
		if err != nil {
			t.Errorf("%s: parse: %v", n, err)
			continue
		}
		if err := d.Verify(name, c.roots, now); err == nil {
			t.Errorf("%s: verified", n)
		}
	}
}

func TestParse(t *testing.T) {
	ca := certtest.NewCA(time.Time{}, time.Time{})
	l := ca.Leaf(name, certtest.Opts{})
	key, chain := string(l.KeyPEM()), string(l.ChainPEM())
	doc := func(m map[string]string) []byte { b, _ := json.Marshal(m); return b }
	if _, err := Parse([]byte(`{}`)); !errors.Is(err, ErrEmpty) {
		t.Fatal("{} is not empty", err)
	}
	if _, err := Parse([]byte(` { } `)); !errors.Is(err, ErrEmpty) {
		t.Fatal("{} with spaces", err)
	}
	for n, b := range map[string][]byte{
		"empty":          nil,
		"null":           []byte(`null`),
		"key only":       doc(map[string]string{"key": key}),
		"chain only":     doc(map[string]string{"chain": chain}),
		"extra member":   doc(map[string]string{"key": key, "chain": chain, "x": "1"}),
		"trailing":       append(doc(map[string]string{"key": key, "chain": chain}), []byte(` {}`)...),
		"chain garbage":  doc(map[string]string{"key": key, "chain": chain + "junk"}),
		"key twice":      doc(map[string]string{"key": key + key, "chain": chain}),
		"key not pkcs8":  doc(map[string]string{"key": strings.Replace(key, "PRIVATE KEY", "EC PRIVATE KEY", 2), "chain": chain}),
		"key in chain":   doc(map[string]string{"key": key, "chain": chain + key}),
		"no certificate": doc(map[string]string{"key": key, "chain": ""}),
		"too large":      doc(map[string]string{"key": key, "chain": chain + strings.Repeat(" ", MaxDocument)}),
	} {
		if _, err := Parse(b); err == nil || errors.Is(err, ErrEmpty) {
			t.Errorf("%s: %v", n, err)
		}
	}
	// No error carries the document.
	_, err := Parse(doc(map[string]string{"key": key, "chain": chain + "junk"}))
	if err == nil || strings.Contains(err.Error(), "PRIVATE") || strings.Contains(err.Error(), "MII") {
		t.Fatal(err)
	}
}

func TestLifeLeft(t *testing.T) {
	now := time.Now()
	c := &x509.Certificate{NotBefore: now.Add(-60 * time.Hour), NotAfter: now.Add(30 * time.Hour)}
	if v := LifeLeft(c, now); v < 33.2 || v > 33.4 {
		t.Fatal(v)
	}
	if LifeLeft(c, now.Add(31*time.Hour)) != 0 || LifeLeft(c, now.Add(-100*time.Hour)) != 100 {
		t.Fatal("bounds")
	}
}

func TestSame(t *testing.T) {
	ca := certtest.NewCA(time.Time{}, time.Time{})
	a, _ := Parse(ca.Leaf(name, certtest.Opts{}).Doc())
	b, _ := Parse(ca.Leaf(name, certtest.Opts{}).Doc())
	a2, _ := Parse(mustMarshal(a))
	if !Same(a, a2) || Same(a, b) || Same(a, nil) || !Same(nil, nil) {
		t.Fatal("Same")
	}
}

func mustMarshal(d *Doc) []byte {
	b, err := d.Marshal()
	if err != nil {
		panic(err)
	}
	return b
}

// Same compares the whole chain, not only the key and the leaf.
func TestSameChain(t *testing.T) {
	ca := certtest.NewCA(time.Time{}, time.Time{})
	other := certtest.NewCA(time.Time{}, time.Time{})
	l := ca.Leaf(name, certtest.Opts{})
	a, _ := Parse(l.Doc())
	b := &Doc{Key: a.Key, Chain: []*x509.Certificate{a.Leaf(), other.Inter}}
	c := &Doc{Key: a.Key, Chain: []*x509.Certificate{a.Leaf()}}
	if Same(a, b) || Same(a, c) {
		t.Fatal("another chain counted as the same")
	}
}

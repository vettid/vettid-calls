package renewer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/tlscert"
)

// The real ACME adapter against Pebble, Let's Encrypt's test CA, with
// pebble-challtestsrv as its DNS: register, issue with DNS-01, renew
// kept, rekey (issue, then revoke the old one), rollover. Skipped unless
// PEBBLE_DIRECTORY (https://localhost:14000/dir), PEBBLE_TLS_CA (the
// file of pebble.minica.pem), PEBBLE_ROOTS (https://localhost:15000)
// and CHALLTESTSRV (http://localhost:8055) are set.
func TestPebble(t *testing.T) {
	dir, caFile, roots, chall := os.Getenv("PEBBLE_DIRECTORY"), os.Getenv("PEBBLE_TLS_CA"), os.Getenv("PEBBLE_ROOTS"), os.Getenv("CHALLTESTSRV")
	if dir == "" || caFile == "" || roots == "" || chall == "" {
		t.Skip("Pebble not set up (PEBBLE_DIRECTORY, PEBBLE_TLS_CA, PEBBLE_ROOTS, CHALLTESTSRV)")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	sec := &fakeSecrets{m: map[string][]byte{"cert": []byte(`{}`), "acct": []byte(`{}`)}, puts: map[string]int{}}
	logs := &bytes.Buffer{}
	r := &Renewer{Name: name, CertSecret: "cert", AccountSecret: "acct", Secrets: sec, DNS: &challDNS{base: chall, hc: http.DefaultClient},
		ACME: NewClient(dir, hc), Metrics: metrics.New("test", nil), Log: slog.New(slog.NewTextHandler(logs, nil))}
	ctx := context.Background()
	run := func(in Input) Result {
		t.Helper()
		res, err := r.Run(ctx, in)
		if err != nil {
			t.Fatalf("%s: %v %+v\n%s", in.Action, err, res, logs.String())
		}
		return res
	}
	res := run(Input{Action: ActionRegister})
	if res.Outcome != OutcomeRegistered || res.AccountURL == "" {
		t.Fatalf("%+v", res)
	}
	r.PinnedAccount = res.AccountURL

	// Pebble's issuing root, for the renewer's check.
	r.Roots = pebbleRoots(t, hc, roots)
	res = run(Input{Action: ActionRenew})
	if res.Outcome != OutcomeIssued {
		t.Fatalf("%+v", res)
	}
	d, err := tlscert.Parse(sec.m["cert"])
	if err != nil || d.Verify(name, r.Roots, time.Now()) != nil {
		t.Fatal("issued certificate", err)
	}
	first := d.Leaf()
	if res := run(Input{Action: ActionRenew}); res.Outcome != OutcomeKept {
		t.Fatalf("%+v", res)
	}
	res = run(Input{Action: ActionRekey})
	if len(res.Revoked) != 1 || res.Revoked[0] != Serial(first) || res.Serial == Serial(first) {
		t.Fatalf("rekey %+v", res)
	}
	run(Input{Action: ActionRollover})
	// The rolled-over key still works on the same account.
	if res := run(Input{Action: ActionForce}); res.Outcome != OutcomeIssued || res.AccountURL != r.PinnedAccount {
		t.Fatalf("after rollover %+v", res)
	}
	t.Logf("account %s; certificates issued and revoked as expected", r.PinnedAccount)
}

func pebbleRoots(t *testing.T, hc *http.Client, base string) *x509.CertPool {
	t.Helper()
	resp, err := hc.Get(base + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		blk, _ := pem.Decode(b)
		t.Fatalf("no root from Pebble: %v", blk)
	}
	return p
}

// challDNS sets TXT records in pebble-challtestsrv.
type challDNS struct {
	base string
	hc   *http.Client
}

func (c *challDNS) post(path string, body any) error {
	b, _ := json.Marshal(body)
	resp, err := c.hc.Post(c.base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("challtestsrv %s: %d", path, resp.StatusCode)
	}
	return nil
}

func (c *challDNS) Upsert(_ context.Context, n, v string) (string, error) {
	return "now", c.post("/set-txt", map[string]string{"host": n + ".", "value": v})
}
func (c *challDNS) WaitInSync(context.Context, string) error { return nil }
func (c *challDNS) Delete(_ context.Context, n, _ string) error {
	return c.post("/clear-txt", map[string]string{"host": n + "."})
}

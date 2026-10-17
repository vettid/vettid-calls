package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/manifest"

	"github.com/vettid/vettid-calls/internal/attest"
	"github.com/vettid/vettid-calls/internal/config"
	"github.com/vettid/vettid-calls/internal/issuer"
	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/nsmtest"
	"github.com/vettid/vettid-calls/internal/turncred"
)

const secDoc = `{"current":"a","secrets":{"a":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}}`

type fixture struct {
	nsm    *nsmtest.NSM
	signer *nsmtest.ManifestSigner
	site   *httptest.Server
	env    map[string]string
	logs   *bytes.Buffer
	rec    *metrics.Recorder
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{nsm: nsmtest.New(0xa0, nil), signer: nsmtest.NewManifestSigner(), logs: &bytes.Buffer{}, rec: &metrics.Recorder{}}
	served := f.signer.Served(1, nsmtest.Release(1, f.nsm.PCR0Hex(), manifest.StatusActive))
	f.site = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(served) }))
	t.Cleanup(f.site.Close)
	f.env = map[string]string{"CALLS_CHANNEL": "staging", "CALLS_TURN_HOST": "turn.staging.vettid.org",
		"CALLS_SECRETS": "env", "CALLS_SECRET_ENV": "TEST_SECRET", "TEST_SECRET": secDoc, "CALLS_METRICS": "none"}
	return f
}

func (f *fixture) lookup(k string) (string, bool) { v, ok := f.env[k]; return v, ok }

func (f *fixture) deps() deps {
	return deps{out: &bytes.Buffer{}, errOut: f.logs, lookup: f.lookup, sink: f.rec, roots: f.nsm.Roots(),
		trust: &attest.Trust{ManifestURL: f.site.URL, ManifestKeys: f.signer.Keys()}}
}

// signed returns a vault request (§5.2) as method, path, headers, body.
func (f *fixture) signed(count int) (http.Header, []byte) {
	body := []byte(`{"count":` + string(rune('0'+count)) + `}`)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := http.Header{}
	bh := relayauth.BodyHash(body)
	relayauth.SetHeaders(h, priv, http.MethodPost, issuer.PathCredentials, time.Now(), bh)
	digest := relayauth.Digest(http.MethodPost, issuer.PathCredentials, h.Get("X-VettID-Timestamp"), bh)
	doc, _ := f.nsm.Attest(digest[:], nil, pub)
	h.Set(issuer.HeaderAttestation, nsmtest.Header(doc))
	return h, body
}

func checkAnswer(t *testing.T, body []byte, n int) {
	t.Helper()
	var a issuer.Answer
	if err := json.Unmarshal(body, &a); err != nil || len(a.Credentials) != n {
		t.Fatalf("%s", body)
	}
	for _, c := range a.Credentials {
		if !turncred.Check([]string{"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}, c.Username, c.Credential, time.Now()) {
			t.Fatal("credential not under the secret")
		}
	}
}

// The HTTP server mode, end to end: health, a valid request, metrics on
// shutdown, one start line and nothing else in the log.
func TestServer(t *testing.T) {
	f := newFixture(t)
	cfg, err := config.Load(f.lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	d := f.deps()
	d.listener = ln
	ready := make(chan struct{})
	d.ready = func(*issuer.Server) { close(ready) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- run(ctx, cfg, d) }()
	<-ready
	base := "http://" + ln.Addr().String()
	resp, err := http.Get(base + issuer.PathHealth)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("health", err)
	}
	resp.Body.Close()
	h, body := f.signed(2)
	req, _ := http.NewRequest(http.MethodPost, base+issuer.PathCredentials, bytes.NewReader(body))
	req.Header = h
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, out.String())
	}
	checkAnswer(t, out.Bytes(), 2)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(f.logs.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "vettid-calls started") {
		t.Fatalf("log:\n%s", f.logs.String())
	}
	var ok bool
	for _, batch := range f.rec.Data {
		for _, dt := range batch {
			if dt.Name == "requests" && dt.Dims[0].Value == "ok" && dt.Value == 1 {
				ok = true
			}
		}
	}
	if !ok {
		t.Fatalf("metrics: %+v", f.rec.Data)
	}
}

// The Lambda mode: a function URL event in, the answer out, metrics put
// after each request.
func TestLambda(t *testing.T) {
	f := newFixture(t)
	f.env["AWS_LAMBDA_RUNTIME_API"] = "127.0.0.1:9001"
	f.env["AWS_REGION"] = "us-east-1"
	cfg, err := config.Load(f.lookup, false)
	if err != nil || !cfg.Lambda {
		t.Fatal(err)
	}
	var handler func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error)
	d := f.deps()
	d.lambdaStart = func(h any) {
		handler = h.(func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error))
	}
	if err := run(context.Background(), cfg, d); err != nil {
		t.Fatal(err)
	}
	h, body := f.signed(3)
	ev := events.LambdaFunctionURLRequest{RawPath: issuer.PathCredentials, Body: string(body), Headers: map[string]string{}}
	ev.RequestContext.HTTP.Method = http.MethodPost
	ev.RequestContext.HTTP.SourceIP = "192.0.2.7"
	for k := range h {
		ev.Headers[strings.ToLower(k)] = h.Get(k)
	}
	resp, err := handler(context.Background(), ev)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %d %s", err, resp.StatusCode, resp.Body)
	}
	checkAnswer(t, []byte(resp.Body), 3)
	if len(f.rec.Data) != 1 {
		t.Fatalf("metrics put %d times", len(f.rec.Data))
	}
	// A base64 body (as a function URL may deliver one) is decoded.
	h, body = f.signed(1)
	ev.Body, ev.IsBase64Encoded = b64(body), true
	for k := range h {
		ev.Headers[strings.ToLower(k)] = h.Get(k)
	}
	resp, _ = handler(context.Background(), ev)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, resp.Body)
	}
	// Two attestation headers, joined by the function URL: refused.
	ev.Headers["x-vettid-attestation"] += "," + ev.Headers["x-vettid-attestation"]
	resp, _ = handler(context.Background(), ev)
	if resp.StatusCode != 403 {
		t.Fatalf("joined headers: %d", resp.StatusCode)
	}
	if strings.Contains(f.logs.String(), "192.0.2.7") {
		t.Fatal("the source address was logged")
	}
}

// -dev accepts the TEST root and refuses the AWS root.
func TestDevRoots(t *testing.T) {
	f := newFixture(t)
	cfg := config.Config{Dev: true, DevNitroRoot: b64(f.nsm.Root.Raw)}
	if _, err := devRoots(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.DevNitroRoot = b64(attest.NitroRoot().Raw)
	if _, err := devRoots(cfg); err == nil {
		t.Fatal("the AWS root was accepted under -dev")
	}
}

// The binary links neither the test NSM nor anything of the tests.
func TestDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("go list")
	}
	for _, pkg := range []string{".", "../turn-agent", "../callsctl"} {
		if _, err := os.Stat(pkg); err != nil {
			continue
		}
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", pkg, err, out)
		}
		if strings.Contains(string(out), "internal/nsmtest") {
			t.Fatalf("%s links internal/nsmtest", pkg)
		}
	}
}

func TestManifestOutcome(t *testing.T) {
	for err, want := range map[error]string{nil: "ok", attest.ErrNotPublished: "not_published",
		attest.ErrFetch: "fetch", attest.ErrRollback: "rollback", manifest.ErrSignature: "invalid"} {
		if got := manifestOutcome(err); got != want {
			t.Errorf("%v: %s", err, got)
		}
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

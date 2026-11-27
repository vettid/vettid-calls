package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/renewer"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{"CALLS_TURN_HOST": "turn.staging.vettid.org", "CALLS_TLS_SECRET_ID": "vettid-org/staging/calls/tls-cert",
		"CALLS_ACME_ACCOUNT_SECRET_ID": "vettid-org/staging/calls/acme-account", "CALLS_ZONE_ID": "Z0123456789ABCDEFGHIJ",
		"AWS_REGION": "us-east-1"}
}

func TestLoad(t *testing.T) {
	c, err := load(env(base()))
	if err != nil || c.directory != renewer.LetsEncrypt || c.pinned != "" || c.namespace != "vettid-calls" {
		t.Fatalf("%v %+v", err, c)
	}
	for name, mut := range map[string]func(map[string]string){
		"no host":        func(m map[string]string) { delete(m, "CALLS_TURN_HOST") },
		"no cert secret": func(m map[string]string) { delete(m, "CALLS_TLS_SECRET_ID") },
		"same secrets":   func(m map[string]string) { m["CALLS_ACME_ACCOUNT_SECRET_ID"] = m["CALLS_TLS_SECRET_ID"] },
		"http directory": func(m map[string]string) { m["CALLS_ACME_DIRECTORY"] = "http://acme.test/dir" },
		"http pinned":    func(m map[string]string) { m["CALLS_ACME_ACCOUNT"] = "http://acme.test/acct/1" },
		"bad zone":       func(m map[string]string) { m["CALLS_ZONE_ID"] = "/hostedzone/Z1" },
		"no region":      func(m map[string]string) { delete(m, "AWS_REGION") },
		"bad namespace":  func(m map[string]string) { m["CALLS_METRICS_NAMESPACE"] = "a b" },
	} {
		m := base()
		mut(m)
		if _, err := load(env(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The handler: an input that fails returns an error naming the step
// only, and the metrics are put either way.
func TestHandler(t *testing.T) {
	rec := &metrics.Recorder{}
	reg := metrics.New("test", nil)
	r := &renewer.Renewer{Name: "turn.staging.vettid.org", CertSecret: "c", AccountSecret: "a", Metrics: reg, Secrets: nilSecrets{}}
	h := handler(r, reg, rec, nil)
	res, err := h(context.Background(), renewer.Input{Action: "delete"})
	if err == nil || err.Error() != "delete failed at input" || res.Step != "input" {
		t.Fatalf("%+v %v", res, err)
	}
	if len(rec.Data) != 1 {
		t.Fatal("metrics not put")
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal(string(b))
	}
}

type nilSecrets struct{}

func (nilSecrets) Get(context.Context, string) ([]byte, error) { return []byte(`{}`), nil }
func (nilSecrets) Put(context.Context, string, []byte) error   { return nil }

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/tlscert"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{"CALLS_TURN_HOST": "turn.staging.vettid.org", "CALLS_PRIVATE_IPV4": "10.40.0.12",
		"CALLS_PUBLIC_IPV4": "198.51.100.20", "CALLS_IPV6": "2600:1f18:1234:5600::20",
		"CALLS_OWN_NETWORKS": "10.40.0.0/16, 2600:1f18:1234:5600::/56",
		"CALLS_SECRET_ID":    "vettid-org/staging/calls/turn-secret", "AWS_REGION": "us-east-1"}
}

func TestLoad(t *testing.T) {
	c, err := load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.secrets != "aws" || c.metrics != "cloudwatch" || len(c.params.OwnNetworks) != 2 || c.params.RunDir != "/run/vettid-calls" {
		t.Fatalf("%+v", c)
	}
	for name, mut := range map[string]func(map[string]string){
		"no public v4":    func(m map[string]string) { delete(m, "CALLS_PUBLIC_IPV4") },
		"bad v6":          func(m map[string]string) { m["CALLS_IPV6"] = "nope" },
		"bad network":     func(m map[string]string) { m["CALLS_OWN_NETWORKS"] = "10.0.0.0" },
		"no secret id":    func(m map[string]string) { delete(m, "CALLS_SECRET_ID") },
		"env secrets":     func(m map[string]string) { m["CALLS_SECRETS"] = "env" },
		"zero quota":      func(m map[string]string) { m["CALLS_TOTAL_QUOTA"] = "0" },
		"bad host":        func(m map[string]string) { m["CALLS_TURN_HOST"] = "Turn Server" },
		"capacity < cap":  func(m map[string]string) { m["CALLS_CAPACITY_KBPS"] = "10" },
		"metrics unknown": func(m map[string]string) { m["CALLS_METRICS"] = "statsd" },
		"two TLS sources": func(m map[string]string) {
			m["CALLS_TLS_SECRET_ID"] = "vettid-org/staging/calls/tls-cert"
			m["CALLS_TLS_FILE"] = "/etc/tls.json"
		},
		"status without TLS": func(m map[string]string) { m["CALLS_TURNS_STATUS"] = "/vettid-org/staging/calls/turns-status" },
		"two statuses": func(m map[string]string) {
			m["CALLS_TLS_FILE"] = "/etc/tls.json"
			m["CALLS_TURNS_STATUS"] = "/vettid-org/staging/calls/turns-status"
			m["CALLS_TURNS_STATUS_FILE"] = "/run/status"
		},
	} {
		m := base()
		mut(m)
		if _, err := load(env(m)); err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), "REDACTED") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLoadTLS(t *testing.T) {
	m := base()
	m["CALLS_TLS_SECRET_ID"] = "vettid-org/staging/calls/tls-cert"
	m["CALLS_TURNS_STATUS"] = "/vettid-org/staging/calls/turns-status"
	c, err := load(env(m))
	if err != nil || c.tlsSecretID == "" || c.statusParam == "" {
		t.Fatalf("%v %+v", err, c)
	}
	if c, err = load(env(base())); err != nil || c.tlsSecretID != "" || c.tlsFile != "" {
		t.Fatalf("TLS off by default: %v %+v", err, c)
	}
}

// The file source: an empty file or one over 16 KiB is ErrInvalid (TLS
// off), a missing one ErrNotFound.
func TestTLSFileSource(t *testing.T) {
	dir := t.TempDir()
	for name, size := range map[string]int{"empty": 0, "too large": tlscert.MaxDocument + 1} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := tlsFileSource(p).Get(context.Background()); !errors.Is(err, secretsrc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p := filepath.Join(dir, "ok")
	_ = os.WriteFile(p, []byte(`{}`), 0o600)
	if b, err := tlsFileSource(p).Get(context.Background()); err != nil || string(b) != `{}` {
		t.Fatal(err)
	}
	if _, err := tlsFileSource(filepath.Join(dir, "absent")).Get(context.Background()); !errors.Is(err, secretsrc.ErrNotFound) {
		t.Fatal(err)
	}
}

// -print-config shows the TLS lines with TLS configured, and no-tls
// without.
func TestPrinted(t *testing.T) {
	c, err := load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if b := string(printed(c)); !strings.Contains(b, "\nno-tls\n") || strings.Contains(b, "tls-listening-port") {
		t.Fatal("without TLS")
	}
	m := base()
	m["CALLS_TLS_SECRET_ID"] = "vettid-org/staging/calls/tls-cert"
	c, _ = load(env(m))
	b := string(printed(c))
	if !strings.Contains(b, "tls-listening-port=443") || !strings.Contains(b, "pkey="+filepath.Join("/run/vettid-calls", "tls-key.pem")) || strings.Contains(b, "secretA") {
		t.Fatalf("with TLS:\n%s", b)
	}
}

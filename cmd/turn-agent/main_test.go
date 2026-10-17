package main

import (
	"strings"
	"testing"
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

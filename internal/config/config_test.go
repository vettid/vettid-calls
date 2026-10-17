package config

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{"CALLS_CHANNEL": "staging", "CALLS_TURN_HOST": "turn.staging.vettid.org",
		"CALLS_SECRET_ID": "vettid-org/staging/calls/turn-secret", "AWS_REGION": "us-east-1"}
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(base()), false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Secrets != SecretsAWS || c.MaxInFlight != 4 || c.Metrics != MetricsEMF || c.Lambda || c.ListenAddr != ":8080" ||
		c.MetricsNamespace != "vettid-calls/staging" {
		t.Fatalf("%+v", c)
	}
	m := base()
	m["AWS_LAMBDA_RUNTIME_API"] = "127.0.0.1:9001"
	c, err = Load(env(m), false)
	if err != nil || !c.Lambda || c.Metrics != MetricsCloudWatch {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]func(map[string]string){
		"no channel":        func(m map[string]string) { delete(m, "CALLS_CHANNEL") },
		"dev channel":       func(m map[string]string) { m["CALLS_CHANNEL"] = "dev" },
		"no host":           func(m map[string]string) { delete(m, "CALLS_TURN_HOST") },
		"host with scheme":  func(m map[string]string) { m["CALLS_TURN_HOST"] = "turn:turn.staging.vettid.org" },
		"no secret id":      func(m map[string]string) { delete(m, "CALLS_SECRET_ID") },
		"none outside -dev": func(m map[string]string) { m["CALLS_SECRETS"] = "none" },
		"file without path": func(m map[string]string) { m["CALLS_SECRETS"] = "file" },
		"inflight 0":        func(m map[string]string) { m["CALLS_MAX_INFLIGHT"] = "0" },
		"bad metrics":       func(m map[string]string) { m["CALLS_METRICS"] = "prometheus" },
		"dev vars, no -dev": func(m map[string]string) { m["CALLS_DEV_PCR0S"] = strings.Repeat("a", 96) },
		"bad log level":     func(m map[string]string) { m["CALLS_LOG_LEVEL"] = "debug" },
		"cloudwatch, region": func(m map[string]string) {
			delete(m, "AWS_REGION")
			m["CALLS_SECRETS"] = "env"
			m["CALLS_SECRET_ENV"] = "X"
			m["CALLS_METRICS"] = "cloudwatch"
		},
	}
	for name, mut := range cases {
		m := base()
		mut(m)
		if _, err := Load(env(m), false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDev(t *testing.T) {
	m := map[string]string{"CALLS_TURN_HOST": "localhost", "CALLS_DEV_NITRO_ROOT": "AAAA",
		"CALLS_DEV_PCR0S": strings.Repeat("a", 96)}
	c, err := Load(env(m), true)
	if err != nil || c.Channel != ChannelDev || c.Secrets != SecretsNone {
		t.Fatalf("%v %+v", err, c)
	}
	m["CALLS_CHANNEL"] = "prod"
	if _, err := Load(env(m), true); err == nil {
		t.Fatal("-dev with the prod channel")
	}
	delete(m, "CALLS_CHANNEL")
	m["CALLS_DEV_PCR0S"] = "abc"
	if _, err := Load(env(m), true); err == nil {
		t.Fatal("a short PCR0")
	}
}

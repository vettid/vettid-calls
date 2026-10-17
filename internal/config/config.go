// Package config loads the issuer's configuration from CALLS_*
// environment variables. Nothing here is secret: the TURN secret comes
// from the secret source, never from this configuration. Every variable is
// documented in README.md; keep the two in sync.
package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vettid/vettid-calls/internal/issuer"
)

// Channels.
const (
	ChannelProd    = "prod"
	ChannelStaging = "staging"
	ChannelDev     = "dev"
)

// Secret sources.
const (
	SecretsAWS  = "aws"
	SecretsFile = "file"
	SecretsEnv  = "env"
	SecretsNone = "none" // dev only: a random secret made at start
)

// Metric sinks.
const (
	MetricsCloudWatch = "cloudwatch"
	MetricsEMF        = "emf"
	MetricsNone       = "none"
)

// Config is the issuer's runtime configuration.
type Config struct {
	Dev    bool // the -dev flag
	Lambda bool // running as an AWS Lambda function (AWS_LAMBDA_RUNTIME_API is set)

	Channel     string // CALLS_CHANNEL: prod | staging (dev under -dev)
	TURNHost    string // CALLS_TURN_HOST
	ListenAddr  string // CALLS_LISTEN_ADDR (not in Lambda)
	MaxInFlight int    // CALLS_MAX_INFLIGHT
	LogLevel    string // CALLS_LOG_LEVEL: info | warn | error

	Secrets    string // CALLS_SECRETS: aws | file | env (| none under -dev)
	SecretID   string // CALLS_SECRET_ID (aws): vettid-org/<stage>/calls/turn-secret
	SecretFile string // CALLS_SECRET_FILE (file)
	SecretEnv  string // CALLS_SECRET_ENV (env): the variable holding the document
	Region     string // AWS_REGION / AWS_DEFAULT_REGION

	Metrics          string // CALLS_METRICS: cloudwatch | emf | none
	MetricsNamespace string // CALLS_METRICS_NAMESPACE

	// -dev only.
	DevNitroRoot     string   // CALLS_DEV_NITRO_ROOT: base64 DER of the dev enclave's TEST root
	DevNitroRootFile string   // CALLS_DEV_NITRO_ROOT_FILE: the same as a PEM file
	DevPCR0s         []string // CALLS_DEV_PCR0S: accepted PCR0s (hex)
}

var (
	pcrRE = regexp.MustCompile(`^[0-9a-f]{96}$`)
	nsRE  = regexp.MustCompile(`^[A-Za-z0-9._/#:-]{1,255}$`)
)

func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Load builds a Config from a lookup function (os.LookupEnv); dev is the
// -dev flag.
func Load(lookup func(string) (string, bool), dev bool) (Config, error) {
	get := func(k string) string {
		v, _ := lookup(k)
		return strings.TrimSpace(v)
	}
	c := Config{Dev: dev, Lambda: get("AWS_LAMBDA_RUNTIME_API") != "", ListenAddr: ":8080",
		MaxInFlight: issuer.DefaultMaxInFlight, LogLevel: "info"}
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	c.Channel = get("CALLS_CHANNEL")
	switch {
	case dev && (c.Channel == "" || c.Channel == ChannelDev):
		c.Channel = ChannelDev
	case dev:
		bad("CALLS_CHANNEL must be dev (or unset) under -dev")
	case c.Channel != ChannelProd && c.Channel != ChannelStaging:
		bad("CALLS_CHANNEL must be prod or staging")
	}
	c.TURNHost = get("CALLS_TURN_HOST")
	if err := issuer.ValidHost(c.TURNHost); err != nil {
		bad("CALLS_TURN_HOST: %v", err)
	}
	if v := get("CALLS_LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := get("CALLS_MAX_INFLIGHT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			bad("CALLS_MAX_INFLIGHT must be 1–1000")
		}
		c.MaxInFlight = n
	}
	if v := get("CALLS_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if c.LogLevel != "info" && c.LogLevel != "warn" && c.LogLevel != "error" {
		bad("CALLS_LOG_LEVEL must be info, warn or error")
	}

	c.Secrets = get("CALLS_SECRETS")
	if c.Secrets == "" {
		c.Secrets = SecretsAWS
		if dev {
			c.Secrets = SecretsNone
		}
	}
	c.SecretID = get("CALLS_SECRET_ID")
	c.SecretFile = get("CALLS_SECRET_FILE")
	c.SecretEnv = get("CALLS_SECRET_ENV")
	c.Region = get("AWS_REGION")
	if c.Region == "" {
		c.Region = get("AWS_DEFAULT_REGION")
	}
	switch c.Secrets {
	case SecretsAWS:
		if c.SecretID == "" {
			bad("CALLS_SECRET_ID is required with CALLS_SECRETS=aws")
		}
		if c.Region == "" {
			bad("AWS_REGION is required with CALLS_SECRETS=aws")
		}
	case SecretsFile:
		if c.SecretFile == "" {
			bad("CALLS_SECRET_FILE is required with CALLS_SECRETS=file")
		}
	case SecretsEnv:
		if c.SecretEnv == "" {
			bad("CALLS_SECRET_ENV is required with CALLS_SECRETS=env")
		}
	case SecretsNone:
		if !dev {
			bad("CALLS_SECRETS=none is for -dev only")
		}
	default:
		bad("CALLS_SECRETS must be aws, file or env")
	}

	c.Metrics = get("CALLS_METRICS")
	if c.Metrics == "" {
		c.Metrics = MetricsEMF
		if c.Lambda {
			c.Metrics = MetricsCloudWatch
		}
	}
	if c.Metrics != MetricsCloudWatch && c.Metrics != MetricsEMF && c.Metrics != MetricsNone {
		bad("CALLS_METRICS must be cloudwatch, emf or none")
	}
	if c.Metrics == MetricsCloudWatch && c.Region == "" {
		bad("AWS_REGION is required with CALLS_METRICS=cloudwatch")
	}
	c.MetricsNamespace = get("CALLS_METRICS_NAMESPACE")
	if c.MetricsNamespace == "" {
		c.MetricsNamespace = "vettid-calls/" + c.Channel
	}
	if !nsRE.MatchString(c.MetricsNamespace) {
		bad("CALLS_METRICS_NAMESPACE is not a CloudWatch namespace")
	}

	c.DevNitroRoot = get("CALLS_DEV_NITRO_ROOT")
	c.DevNitroRootFile = get("CALLS_DEV_NITRO_ROOT_FILE")
	c.DevPCR0s = list(get("CALLS_DEV_PCR0S"))
	if dev {
		if (c.DevNitroRoot == "") == (c.DevNitroRootFile == "") {
			bad("-dev needs exactly one of CALLS_DEV_NITRO_ROOT and CALLS_DEV_NITRO_ROOT_FILE")
		}
		if len(c.DevPCR0s) == 0 {
			bad("-dev needs CALLS_DEV_PCR0S")
		}
		for _, p := range c.DevPCR0s {
			if !pcrRE.MatchString(p) {
				bad("CALLS_DEV_PCR0S: each PCR0 is 96 lower-case hex digits")
			}
		}
	} else if c.DevNitroRoot != "" || c.DevNitroRootFile != "" || len(c.DevPCR0s) > 0 {
		bad("CALLS_DEV_* variables are for -dev only")
	}
	return c, errors.Join(errs...)
}

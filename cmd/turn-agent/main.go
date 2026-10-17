// Command turn-agent runs beside coturn in the calling service's server
// image (CALLING-SERVICE §4.4): it reads the TURN secret, renders coturn's
// configuration, runs coturn, and turns coturn's counters into metrics
// once a minute (§10). It is the image's entry point.
//
// Configuration is by CALLS_* environment variables (README.md).
//
//	turn-agent                 run coturn under the agent
//	turn-agent -print-config   print the configuration it would render, with
//	                           the secrets replaced by REDACTED, and exit
//	turn-agent -version        print the version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/vettid/vettid-calls/internal/attest"
	"github.com/vettid/vettid-calls/internal/awsx"
	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/turnagent"
)

const specVersion = "0.2.0"

var version string

func buildVersion() string {
	rev := version
	if rev == "" {
		rev = "unknown"
		if bi, ok := debug.ReadBuildInfo(); ok {
			rev = bi.Main.Version
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					rev = s.Value
				}
			}
		}
	}
	return "turn-agent " + rev + " (CALLING-SERVICE " + specVersion + ", coturn 4.18.0)"
}

// config is turn-agent's configuration.
type config struct {
	params     turnagent.Params
	secrets    string // aws | file
	secretID   string
	secretFile string
	region     string
	metrics    string // cloudwatch | emf | none
	namespace  string
	turnserver string
}

func load(lookup func(string) (string, bool)) (config, error) {
	get := func(k string) string { v, _ := lookup(k); return strings.TrimSpace(v) }
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	c := config{secrets: "aws", metrics: "cloudwatch", namespace: "vettid-calls", turnserver: "/usr/bin/turnserver"}
	c.params.Realm = get("CALLS_TURN_HOST")
	c.params.RunDir = "/run/vettid-calls"
	if v := get("CALLS_RUN_DIR"); v != "" {
		c.params.RunDir = v
	}
	addr := func(k string, required bool) netip.Addr {
		v := get(k)
		if v == "" {
			if required {
				bad("%s is required", k)
			}
			return netip.Addr{}
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			bad("%s is not an IP address", k)
		}
		return a
	}
	c.params.PrivateIPv4 = addr("CALLS_PRIVATE_IPV4", true)
	c.params.PublicIPv4 = addr("CALLS_PUBLIC_IPV4", true)
	c.params.IPv6 = addr("CALLS_IPV6", false)
	for _, s := range strings.Split(get("CALLS_OWN_NETWORKS"), ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			bad("CALLS_OWN_NETWORKS: %q is not a CIDR block", s)
			continue
		}
		c.params.OwnNetworks = append(c.params.OwnNetworks, p)
	}
	num := func(k string, dst *int) {
		if v := get(k); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				bad("%s must be a positive integer", k)
			}
			*dst = n
		}
	}
	num("CALLS_MAX_KBPS", &c.params.MaxKbps)
	num("CALLS_CAPACITY_KBPS", &c.params.CapacityKbps)
	num("CALLS_USER_QUOTA", &c.params.UserQuota)
	num("CALLS_TOTAL_QUOTA", &c.params.TotalQuota)
	if v := get("CALLS_SECRETS"); v != "" {
		c.secrets = v
	}
	c.secretID, c.secretFile = get("CALLS_SECRET_ID"), get("CALLS_SECRET_FILE")
	c.region = get("AWS_REGION")
	if c.region == "" {
		c.region = get("AWS_DEFAULT_REGION")
	}
	switch c.secrets {
	case "aws":
		if c.secretID == "" || c.region == "" {
			bad("CALLS_SECRETS=aws needs CALLS_SECRET_ID and AWS_REGION")
		}
	case "file":
		if c.secretFile == "" {
			bad("CALLS_SECRETS=file needs CALLS_SECRET_FILE")
		}
	default:
		bad("CALLS_SECRETS must be aws or file")
	}
	if v := get("CALLS_METRICS"); v != "" {
		c.metrics = v
	}
	if c.metrics != "cloudwatch" && c.metrics != "emf" && c.metrics != "none" {
		bad("CALLS_METRICS must be cloudwatch, emf or none")
	}
	if c.metrics == "cloudwatch" && c.region == "" {
		bad("CALLS_METRICS=cloudwatch needs AWS_REGION")
	}
	if v := get("CALLS_METRICS_NAMESPACE"); v != "" {
		c.namespace = v
	}
	if v := get("CALLS_TURNSERVER"); v != "" {
		c.turnserver = v
	}
	// Render once with placeholders: every parameter error shows now.
	p := c.params
	p.Secrets = []string{"REDACTED"}
	if _, err := turnagent.Render(p); err != nil {
		bad("%v", err)
	}
	return c, errors.Join(errs...)
}

func main() {
	printConfig := flag.Bool("print-config", false, "print the configuration with the secrets replaced, and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildVersion())
		return
	}
	cfg, err := load(os.LookupEnv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "turn-agent: invalid configuration:", err)
		os.Exit(2)
	}
	if *printConfig {
		p := cfg.params
		p.Secrets = []string{"REDACTED"}
		b, _ := turnagent.Render(p)
		os.Stdout.Write(b)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "turn-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	reg := metrics.New(cfg.namespace, nil)
	var src secretsrc.Source = secretsrc.File(cfg.secretFile)
	var sink metrics.Sink = metrics.Discard{}
	if cfg.secrets == "aws" || cfg.metrics == "cloudwatch" {
		a, err := awsx.Load(ctx, cfg.region)
		if err != nil {
			return fmt.Errorf("AWS configuration: %w", err)
		}
		if cfg.secrets == "aws" {
			src = awsx.NewSecret(a, cfg.secretID)
		}
		if cfg.metrics == "cloudwatch" {
			sink = awsx.NewCloudWatch(a)
		}
	}
	if cfg.metrics == "emf" {
		sink = &metrics.EMF{W: os.Stdout}
	}
	if err := os.MkdirAll(cfg.params.RunDir, 0o700); err != nil {
		return errors.New("creating the run directory failed")
	}
	logger.Info("turn-agent started", "version", buildVersion(), "realm", cfg.params.Realm, "secrets", cfg.secrets, "metrics", cfg.metrics)
	a := &turnagent.Agent{
		Params:  cfg.params,
		Secrets: &secretsrc.Holder{Source: src, Now: attest.WallClock},
		Metrics: reg,
		Sink:    sink,
		Start:   turnagent.ExecStarter(cfg.turnserver),
		Scrape:  turnagent.HTTPScraper(promPort(cfg.params)),
		Log:     logger,
	}
	return a.Run(ctx)
}

func promPort(p turnagent.Params) int {
	if p.PrometheusPort != 0 {
		return p.PrometheusPort
	}
	return turnagent.DefaultPromPort
}

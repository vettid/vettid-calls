// Command calls-renewer is the calling service's certificate renewer
// (CALLING-SERVICE 0.3.0 §8.5): a function, run once a day by its
// schedule (action renew) and by the operator (register, renew, force,
// rekey, revoke, rollover). It gets and renews the TURN server's Let's
// Encrypt certificate with DNS-01 on Route 53 and keeps it in the
// certificate secret, off the server.
//
// Configuration is by CALLS_* environment variables (README.md). Its
// answer and its log carry no key material.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/vettid/vettid-calls/internal/awsx"
	"github.com/vettid/vettid-calls/internal/issuer"
	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/renewer"
	"github.com/vettid/vettid-calls/internal/tlscert"
)

var version = ""

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return "unknown"
}

type config struct {
	host, certSecret, accountSecret, pinned, directory, zoneID, region, namespace string
}

var (
	zoneRE = regexp.MustCompile(`^Z[A-Z0-9]{1,31}$`)
	nsRE   = regexp.MustCompile(`^[A-Za-z0-9._/#:-]{1,255}$`)
)

func load(lookup func(string) (string, bool)) (config, error) {
	get := func(k string) string { v, _ := lookup(k); return strings.TrimSpace(v) }
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	c := config{host: get("CALLS_TURN_HOST"), certSecret: get("CALLS_TLS_SECRET_ID"), accountSecret: get("CALLS_ACME_ACCOUNT_SECRET_ID"),
		pinned: get("CALLS_ACME_ACCOUNT"), directory: get("CALLS_ACME_DIRECTORY"), zoneID: get("CALLS_ZONE_ID"),
		region: get("AWS_REGION"), namespace: get("CALLS_METRICS_NAMESPACE")}
	if err := issuer.ValidHost(c.host); err != nil {
		bad("CALLS_TURN_HOST: %v", err)
	}
	if c.certSecret == "" || c.accountSecret == "" || c.certSecret == c.accountSecret {
		bad("CALLS_TLS_SECRET_ID and CALLS_ACME_ACCOUNT_SECRET_ID are required and differ")
	}
	if c.pinned != "" && !strings.HasPrefix(c.pinned, "https://") {
		bad("CALLS_ACME_ACCOUNT must be an https URL")
	}
	if c.directory == "" {
		c.directory = renewer.LetsEncrypt
	}
	if !strings.HasPrefix(c.directory, "https://") {
		bad("CALLS_ACME_DIRECTORY must be an https URL")
	}
	if !zoneRE.MatchString(c.zoneID) {
		bad("CALLS_ZONE_ID must be a Route 53 hosted zone id")
	}
	if c.region == "" {
		bad("AWS_REGION is required")
	}
	if c.namespace == "" {
		c.namespace = "vettid-calls"
	}
	if !nsRE.MatchString(c.namespace) {
		bad("CALLS_METRICS_NAMESPACE is not a CloudWatch namespace")
	}
	return c, errors.Join(errs...)
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := load(os.LookupEnv)
	if err != nil {
		logger.Error("calls-renewer: invalid configuration", "error", err.Error())
		os.Exit(2)
	}
	ctx := context.Background()
	a, err := awsx.Load(ctx, cfg.region)
	if err != nil {
		logger.Error("calls-renewer: AWS configuration", "error", err.Error())
		os.Exit(1)
	}
	reg := metrics.New(cfg.namespace, nil)
	sink := awsx.NewCloudWatch(a)
	r := &renewer.Renewer{Name: cfg.host, CertSecret: cfg.certSecret, AccountSecret: cfg.accountSecret, PinnedAccount: cfg.pinned,
		Secrets: awsx.NewSecrets(a, max(tlscert.MaxDocument, renewer.MaxAccountDocument)),
		DNS:     awsx.NewRoute53TXT(a, cfg.zoneID), ACME: renewer.NewClient(cfg.directory, renewer.HTTPClient()),
		Metrics: reg, Log: logger}
	logger.Info("calls-renewer started", "version", buildVersion(), "name", cfg.host, "directory", cfg.directory,
		"pinned_account", cfg.pinned)
	lambda.Start(handler(r, reg, sink, logger))
}

// handler runs one action and puts its metrics; an error fails the
// invocation, which the renewer-errors alarm counts (§10). The function
// is never retried (MaximumRetryAttempts 0, in the stack).
func handler(r *renewer.Renewer, reg *metrics.Registry, sink metrics.Sink, log *slog.Logger) func(context.Context, renewer.Input) (renewer.Result, error) {
	return func(ctx context.Context, in renewer.Input) (renewer.Result, error) {
		res, err := r.Run(ctx, in)
		if ferr := metrics.Flush(context.WithoutCancel(ctx), reg, sink); ferr != nil {
			log.Error("calls-renewer: putting metrics failed")
		}
		if err != nil {
			return res, fmt.Errorf("%s failed at %s", res.Action, res.Step)
		}
		return res, nil
	}
}

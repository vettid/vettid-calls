package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/vettid/vettid-calls/internal/attest"
	"github.com/vettid/vettid-calls/internal/awsx"
	"github.com/vettid/vettid-calls/internal/config"
	"github.com/vettid/vettid-calls/internal/issuer"
	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/turncred"
)

// deps are run's connections to the outside, replaced in tests.
type deps struct {
	out    io.Writer // EMF metrics
	errOut io.Writer // the log
	lookup func(string) (string, bool)
	// listener, if set, replaces listening on cfg.ListenAddr (tests).
	listener net.Listener
	// trust, if set, replaces the channel's compiled-in pins (tests).
	trust *attest.Trust
	// roots, if set, replaces the pinned AWS Nitro root (tests).
	roots *x509.CertPool
	// sink, if set, replaces the configured metric sink (tests).
	sink metrics.Sink
	// lambdaStart, if set, replaces lambda.Start (tests).
	lambdaStart func(any)
	// ready, if set, is called with the server once it is serving.
	ready func(*issuer.Server)
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

// manifestOutcome maps a refresh result to the closed set of the
// manifest_refresh metric.
func manifestOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, attest.ErrNotPublished):
		return "not_published"
	case errors.Is(err, attest.ErrFetch):
		return "fetch"
	case errors.Is(err, attest.ErrRollback):
		return "rollback"
	default:
		return "invalid"
	}
}

// devRoots reads the dev enclave's TEST Nitro root (-dev only) and refuses
// the AWS root: a "dev" issuer that trusted real enclaves would be an
// issuer that skips the manifest.
func devRoots(cfg config.Config) (*x509.CertPool, error) {
	var der []byte
	if cfg.DevNitroRootFile != "" {
		b, err := os.ReadFile(cfg.DevNitroRootFile)
		if err != nil {
			return nil, fmt.Errorf("reading the dev Nitro root: %w", err)
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("the dev Nitro root file is not PEM")
		}
		der = blk.Bytes
	} else {
		b, err := base64.StdEncoding.DecodeString(cfg.DevNitroRoot)
		if err != nil {
			return nil, errors.New("CALLS_DEV_NITRO_ROOT is not base64")
		}
		der = b
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("the dev Nitro root is not a certificate")
	}
	if cert.Equal(attest.NitroRoot()) {
		return nil, errors.New("-dev refuses the AWS Nitro Enclaves root: the stand-in takes the dev enclave's TEST root only")
	}
	p := x509.NewCertPool()
	p.AddCert(cert)
	return p, nil
}

func run(ctx context.Context, cfg config.Config, d deps) error {
	logger := newLogger(d.errOut, cfg.LogLevel)
	reg := metrics.New(cfg.MetricsNamespace, attest.WallClock)

	var awsCfg aws.Config
	needAWS := cfg.Secrets == config.SecretsAWS || (cfg.Metrics == config.MetricsCloudWatch && d.sink == nil)
	if needAWS {
		a, err := awsx.Load(ctx, cfg.Region)
		if err != nil {
			return fmt.Errorf("AWS configuration: %w", err)
		}
		awsCfg = a
	}

	// The metric sink.
	sink := d.sink
	if sink == nil {
		switch cfg.Metrics {
		case config.MetricsCloudWatch:
			sink = awsx.NewCloudWatch(awsCfg)
		case config.MetricsEMF:
			sink = &metrics.EMF{W: d.out}
		default:
			sink = metrics.Discard{}
		}
	}

	// The secret.
	var src secretsrc.Source
	switch cfg.Secrets {
	case config.SecretsAWS:
		src = awsx.NewSecret(awsCfg, cfg.SecretID)
	case config.SecretsFile:
		src = secretsrc.File(cfg.SecretFile)
	case config.SecretsEnv:
		src = secretsrc.Env{Name: cfg.SecretEnv, Lookup: d.lookup}
	case config.SecretsNone:
		s, err := turncred.NewSet(time.Now(), nil)
		if err != nil {
			return err
		}
		b, err := s.Marshal()
		if err != nil {
			return err
		}
		src = secretsrc.Static(b)
	}
	var srv *issuer.Server
	holder := &secretsrc.Holder{Source: src, Report: func(err error) {
		outcome := "ok"
		if err != nil {
			outcome = "error"
			if srv != nil {
				srv.LogError("secret_refresh", "reading the TURN secret failed", "error", err.Error())
			}
		}
		reg.Count("secret_refresh", metrics.Dim{Name: "outcome", Value: outcome})
	}}

	// The attestation verifier.
	verifier := &attest.Verifier{Roots: attest.NitroRoots(), Now: attest.WallClock}
	if d.roots != nil {
		verifier.Roots = d.roots
	}
	var lazy *attest.Lazy
	if cfg.Dev {
		roots, err := devRoots(cfg)
		if err != nil {
			return err
		}
		verifier.Roots, verifier.Releases = roots, attest.StaticReleases(cfg.DevPCR0s)
	} else {
		trust, err := attest.TrustFor(cfg.Channel)
		if err != nil {
			return err
		}
		if d.trust != nil {
			trust = *d.trust
		}
		m := &attest.Manifests{URL: trust.ManifestURL, Keys: trust.ManifestKeys, Now: attest.WallClock}
		verifier.Releases = m
		lazy = &attest.Lazy{M: m, Report: func(err error) {
			reg.Count("manifest_refresh", metrics.Dim{Name: "outcome", Value: manifestOutcome(err)})
			if err != nil && srv != nil {
				srv.LogError("manifest_refresh", "refreshing the release manifest failed", "outcome", manifestOutcome(err))
			}
		}}
	}

	var err error
	srv, err = issuer.New(issuer.Config{Attest: verifier, Manifest: lazy, Secrets: holder, TURNHost: cfg.TURNHost,
		MaxInFlight: cfg.MaxInFlight, Metrics: reg, Log: logger, Now: attest.WallClock})
	if err != nil {
		return err
	}
	mode := "server"
	if cfg.Lambda {
		mode = "lambda"
	}
	// The one start line: nothing secret, nothing of a request.
	logger.Info("vettid-calls started", "version", buildVersion(), "channel", cfg.Channel, "mode", mode,
		"turn_host", cfg.TURNHost, "max_inflight", cfg.MaxInFlight, "secrets", cfg.Secrets, "metrics", cfg.Metrics, "dev", cfg.Dev)
	srv.Warm(ctx)
	if d.ready != nil {
		d.ready(srv)
	}

	if cfg.Lambda {
		start := d.lambdaStart
		if start == nil {
			start = lambdaStart
		}
		start(lambdaHandler(srv, func(ctx context.Context) {
			// After each request: a function may be frozen or ended at
			// any moment once it has answered, so nothing waits for a
			// timer. PutMetricData keeps standard-resolution data per
			// minute; no log line is written per request (§3 item 5).
			if err := metrics.Flush(ctx, reg, sink); err != nil {
				srv.LogError("metrics", "putting metrics failed")
			}
		}))
		return nil
	}
	return serve(ctx, cfg, d, srv, reg, sink)
}

func serve(ctx context.Context, cfg config.Config, d deps, srv *issuer.Server, reg *metrics.Registry, sink metrics.Sink) error {
	ln := d.listener
	if ln == nil {
		var err error
		if ln, err = net.Listen("tcp", cfg.ListenAddr); err != nil {
			return err
		}
	}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		// The standard library's own error lines can name a client
		// address; they are discarded (§10).
		ErrorLog: log.New(io.Discard, "", 0)}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			_ = metrics.Flush(ctx, reg, sink)
		case err := <-errc:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := hs.Shutdown(sctx)
			cancel()
			_ = metrics.Flush(context.Background(), reg, sink)
			return err
		}
	}
}

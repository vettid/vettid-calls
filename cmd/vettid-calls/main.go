// Command vettid-calls runs the VettID calling service's credential
// issuer (CALLING-SERVICE §5): it gives short-lived TURN credentials to
// attested VettID vaults, and keeps and writes nothing.
//
// It runs as an AWS Lambda function when AWS_LAMBDA_RUNTIME_API is set
// (the staging deployment, behind CloudFront: §8.2) and as an HTTP server
// otherwise (self-hosting, development). Configuration is by CALLS_*
// environment variables (README.md).
//
//	vettid-calls               run the issuer
//	vettid-calls -dev          run the development stand-in: it accepts the dev
//	                           enclave's TEST attestation (never in production)
//	vettid-calls -version      print the version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/vettid/vettid-calls/internal/config"
)

// specVersion is the CALLING-SERVICE version this issuer implements.
const specVersion = "0.2.0"

// version is stamped at build time (-ldflags "-X main.version=..."); when
// empty, the VCS revision embedded by the Go toolchain is used.
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
	return "vettid-calls " + rev + " (CALLING-SERVICE " + specVersion + ")"
}

func main() {
	dev := flag.Bool("dev", false, "run the development stand-in (TEST attestation; never in production)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildVersion())
		return
	}
	cfg, err := config.Load(os.LookupEnv, *dev)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vettid-calls: invalid configuration:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, cfg, deps{out: os.Stdout, errOut: os.Stderr, lookup: os.LookupEnv}); err != nil {
		fmt.Fprintln(os.Stderr, "vettid-calls:", err)
		os.Exit(1)
	}
}

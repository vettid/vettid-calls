package turnagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/tlscert"
	"github.com/vettid/vettid-calls/internal/turnsstatus"
)

// The files coturn reads, in the run directory (§8.5).
const (
	TLSChainName = "tls-chain.pem"
	TLSKeyName   = "tls-key.pem"
)

// TLS timings (§8.5).
const (
	// TLSRefresh: the certificate secret is read with the TURN secret.
	TLSRefresh = secretsrc.RefreshInterval
	// TLSRetry is the least time between two failed reads.
	TLSRetry = secretsrc.RetryInterval
	// StatusRefresh: the status is put again this often while verified.
	StatusRefresh = 10 * time.Minute
	// ReloadTimeout: a SIGUSR2 whose certificate is still not served
	// this long after is followed by a restart.
	ReloadTimeout = 10 * time.Minute
)

// reloadSignal is SIGUSR2 on Linux (12), which coturn 4.18.0 takes as
// "reload the TLS certificates"; the image runs on Linux only
// (reload_linux_test.go checks the number).
const reloadSignal = syscall.Signal(12)

// StatusPutter puts the server's TLS status for the issuer (an SSM
// parameter, or a file).
type StatusPutter interface {
	Put(ctx context.Context, value []byte) error
}

// TLS is TURN over TLS on 443 (CALLING-SERVICE 0.3.0 §8.5). An Agent
// without one runs coturn with no-tls, as before.
type TLS struct {
	// Source is the certificate secret's document (tlscert).
	Source secretsrc.Source
	// Status, if set, is where the status for the issuer goes.
	Status StatusPutter
	// Roots verify the certificate and the served chain (nil: the
	// system's, which in the image are the image's).
	Roots *x509.CertPool
	// Dial makes the minute's handshake and returns the served leaf,
	// verified against cfg (nil: a real TLS dial).
	Dial func(ctx context.Context, addr string, cfg *tls.Config) (*x509.Certificate, error)
	// Now is the clock (default: the wall clock without its monotonic
	// reading).
	Now func() time.Time

	// The rest is Run's own.
	inUse        *tlscert.Doc      // the last valid document read
	prevLeaf     *x509.Certificate // the leaf before a SIGUSR2
	prevOK       bool              // prevLeaf is accepted at the next handshake
	loaded, last time.Time         // the last answered read, the last attempt
	pending      bool              // files written, SIGUSR2 not sent yet
	reloadAt     time.Time         // when SIGUSR2 was sent; zero: none waits
	published    bool              // the last status put says verified
	statusAt     time.Time         // when it was put
}

func (t *TLS) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now().Round(0)
}

// load reads the certificate secret when TLSRefresh has passed (or never
// read), keeping the certificate in use across a failed read, and writes
// a new valid one's files. running is whether coturn runs with TLS now.
func (a *Agent) tlsLoad(ctx context.Context, running bool) {
	t := a.TLS
	now := t.now()
	fresh := !t.loaded.IsZero() && now.Sub(t.loaded) < TLSRefresh && now.Sub(t.loaded) >= 0
	retryOK := t.last.IsZero() || now.Sub(t.last) >= TLSRetry || now.Before(t.last)
	if fresh || !retryOK {
		return
	}
	t.last = now
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := t.Source.Get(rctx)
	if err != nil && !errors.Is(err, secretsrc.ErrNotFound) {
		a.fail("tls_read", errors.New("turnagent: reading the TLS certificate failed; the one in use stays"))
		return
	}
	t.loaded = now
	var d *tlscert.Doc
	if err == nil {
		d, err = tlscert.Parse(b)
	}
	if err == nil {
		err = d.Verify(a.Params.Realm, t.Roots, now)
	}
	if err != nil {
		// Empty, missing or failing the checks: no certificate is used.
		a.fail("tls_invalid", err)
		t.inUse, t.prevLeaf, t.pending = nil, nil, false
		return
	}
	if tlscert.Same(d, t.inUse) {
		return
	}
	if err := a.writeTLS(d); err != nil {
		a.fail("config", err)
		return
	}
	if running && t.inUse != nil {
		t.prevLeaf, t.pending = t.inUse.Leaf(), true
	}
	t.inUse = d
}

// writeTLS writes the re-encoded chain and key for coturn, readable by
// this user only (coturn runs as the same user).
func (a *Agent) writeTLS(d *tlscert.Doc) error {
	key, chain, err := d.Encode()
	if err != nil {
		return err
	}
	for name, b := range map[string][]byte{TLSKeyName: key, TLSChainName: chain} {
		path := filepath.Join(a.Params.RunDir, name)
		if err := os.WriteFile(path+".tmp", b, 0o600); err != nil {
			return errors.New("turnagent: writing the TLS files failed")
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return errors.New("turnagent: writing the TLS files failed")
		}
	}
	return nil
}

// tlsFiles is what coturn is rendered with now: the files while a
// certificate is in use, else nil (no-tls).
func (a *Agent) tlsFiles() *TLSFiles {
	if a.TLS == nil || a.TLS.inUse == nil {
		return nil
	}
	return &TLSFiles{Chain: filepath.Join(a.Params.RunDir, TLSChainName), Key: filepath.Join(a.Params.RunDir, TLSKeyName)}
}

// tlsStep is the minute's TLS work while coturn may run (cur). It returns
// a restart reason when coturn must start again: "tls" when TLS is to be
// switched on or off, "tls_reload" when a reload did not take.
func (a *Agent) tlsStep(ctx context.Context, cur *running) string {
	t := a.TLS
	a.tlsLoad(ctx, cur != nil && cur.tls)
	now := t.now()
	if t.inUse != nil && !now.Before(t.inUse.Leaf().NotAfter) {
		a.fail("tls_invalid", errors.New("turnagent: the TLS certificate has ended"))
		t.inUse, t.prevLeaf, t.pending = nil, nil, false
	}
	if cur == nil {
		return ""
	}
	if cur.tls != (t.inUse != nil) {
		return "tls"
	}
	if !cur.tls {
		a.Metrics.Set("tls", "Count", 0)
		if t.published {
			a.putStatus(ctx, turnsstatus.Status{}) // TLS is off: at once
		}
		return ""
	}
	if t.pending && cur.promUp {
		// Only once coturn answers on its Prometheus port: in 4.18.0 the
		// listeners come up before the SIGUSR2 handler is installed.
		if err := cur.proc.Signal(reloadSignal); err == nil {
			t.pending, t.prevOK, t.reloadAt = false, true, now
		}
	}
	served, ok := a.probe(ctx)
	if ok {
		a.Metrics.Set("tls", "Count", 1)
		a.Metrics.Set("tls_served_life_left", "Percent", tlscert.LifeLeft(served, now))
		if !t.published || now.Sub(t.statusAt) >= StatusRefresh {
			a.putStatus(ctx, turnsstatus.Status{VerifiedAt: now.Unix(), NotAfter: served.NotAfter.Unix()})
		}
	} else {
		// No status is put: it stops being refreshed and ages out at the
		// issuer, so one failure does not take turns: away (§8.5).
		a.Metrics.Set("tls", "Count", 0)
	}
	if !t.reloadAt.IsZero() {
		switch {
		case served != nil && served.Equal(t.inUse.Leaf()):
			t.reloadAt, t.prevLeaf = time.Time{}, nil
		case now.Sub(t.reloadAt) >= ReloadTimeout:
			t.reloadAt, t.prevLeaf = time.Time{}, nil
			return "tls_reload"
		}
	}
	return ""
}

// probe makes the minute's handshake to the server's own 443 on each of
// its addresses, with its name as SNI, verifying the chain; ok when every
// one serves the certificate in use (or, at the first handshake after a
// SIGUSR2, the one before).
func (a *Agent) probe(ctx context.Context) (*x509.Certificate, bool) {
	t := a.TLS
	acceptPrev := t.prevOK
	t.prevOK = false
	dial := t.Dial
	if dial == nil {
		dial = dialLeaf
	}
	cfg := &tls.Config{ServerName: a.Params.Realm, RootCAs: t.Roots, MinVersion: tls.VersionTLS12}
	addrs := []string{a.Params.PrivateIPv4.String()}
	if a.Params.IPv6.IsValid() {
		addrs = append(addrs, a.Params.IPv6.String())
	}
	var served *x509.Certificate
	ok := true
	for _, ip := range addrs {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		leaf, err := dial(pctx, net.JoinHostPort(ip, strconv.Itoa(TLSPort)), cfg)
		cancel()
		switch {
		case err != nil:
			a.fail("tls_probe", errors.New("turnagent: the TLS handshake to "+ip+" failed"))
			ok = false
		case !leaf.Equal(t.inUse.Leaf()) && !(acceptPrev && t.prevLeaf != nil && leaf.Equal(t.prevLeaf)):
			a.fail("tls_probe", errors.New("turnagent: "+ip+" serves another certificate"))
			ok, served = false, leaf
		case served == nil:
			served = leaf
		}
	}
	return served, ok
}

func dialLeaf(ctx context.Context, addr string, cfg *tls.Config) (*x509.Certificate, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("turnagent: no certificate served")
	}
	return certs[0], nil
}

// putStatus puts the status for the issuer; a failure is tls_status and
// is tried again at the next step.
func (a *Agent) putStatus(ctx context.Context, s turnsstatus.Status) {
	t := a.TLS
	if t.Status == nil {
		t.published, t.statusAt = s.VerifiedAt > 0, t.now()
		return
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := t.Status.Put(pctx, s.Encode()); err != nil {
		a.fail("tls_status", errors.New("turnagent: putting the TLS status failed"))
		return
	}
	t.published, t.statusAt = s.VerifiedAt > 0, t.now()
}

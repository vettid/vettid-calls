// Package renewer is the calling service's certificate renewer
// (CALLING-SERVICE 0.3.0 §8.5): it gets and renews the Let's Encrypt
// certificate of turn.<stage>.vettid.org with DNS-01 on Route 53, and
// keeps the certificate and its key in the certificate secret, off the
// TURN server.
//
// It never logs or returns key material: its result and its log carry
// the action, the outcome, the account URL (not a secret), serials, and
// on a failure the step that failed.
package renewer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/tlscert"
)

// Actions (the input's action, §8.5).
const (
	ActionRegister = "register"
	ActionRenew    = "renew"
	ActionForce    = "force"
	ActionRekey    = "rekey"
	ActionRevoke   = "revoke"
	ActionRollover = "rollover"
)

// Outcomes (renew{outcome}, §10).
const (
	OutcomeKept       = "kept"
	OutcomeIssued     = "issued"
	OutcomeRegistered = "registered"
	OutcomeRevoked    = "revoked"
	OutcomeFailed     = "failed"
)

// Deadline is the run's own limit, under the function's 5 minutes, so
// that the TXT record is deleted and the failure reported before the
// function is stopped.
const Deadline = 4 * time.Minute

// RenewAt: a certificate with less than this share of its lifetime left
// is renewed (a third: 30 days of a 90-day certificate).
const RenewAt = 100.0 / 3

// Input is the function's input.
type Input struct {
	Action string `json:"action"`
	// Serials (revoke only): which listed certificates to revoke; none:
	// every listed one but the certificate secret's current one.
	Serials []string `json:"serials,omitempty"`
	// Current (revoke only) allows revoking the current certificate.
	Current bool `json:"current,omitempty"`
}

// Result is the function's answer: no key material.
type Result struct {
	Action     string   `json:"action"`
	Outcome    string   `json:"outcome"`
	Step       string   `json:"step,omitempty"`
	AccountURL string   `json:"account_url,omitempty"`
	Serial     string   `json:"serial,omitempty"`  // the certificate held after the run
	Revoked    []string `json:"revoked,omitempty"` // serials
	NotRevoked []string `json:"not_revoked,omitempty"`
}

// Order is an ACME order being filled.
type Order struct {
	URL   string
	Authz []string
}

// Challenge is a DNS-01 challenge and its TXT record's value.
type Challenge struct {
	URL, Token, Record string
	// Done: the authorization is already valid (the CA reused it);
	// nothing is to be answered.
	Done bool
	// Raw is the client's own value, passed back to Accept.
	Raw any
}

// ACME is what the renewer needs of the CA, for one account key.
type ACME interface {
	Register(ctx context.Context) (accountURL string, err error)
	Order(ctx context.Context, name string) (*Order, error)
	DNSChallenge(ctx context.Context, authzURL string) (*Challenge, error)
	Accept(ctx context.Context, c *Challenge) error
	WaitAuthorization(ctx context.Context, authzURL string) error
	Finalize(ctx context.Context, orderURL string, csr []byte) (chain [][]byte, err error)
	Revoke(ctx context.Context, der []byte) error
	Rollover(ctx context.Context, newKey crypto.Signer) error
}

// DNS writes and deletes the challenge's TXT record.
type DNS interface {
	// Upsert writes value as the name's one TXT record and returns the
	// change, to wait for.
	Upsert(ctx context.Context, name, value string) (change string, err error)
	WaitInSync(ctx context.Context, change string) error
	Delete(ctx context.Context, name, value string) error
}

// Secrets reads and puts the two secrets (no create, no delete).
type Secrets interface {
	Get(ctx context.Context, id string) ([]byte, error)
	Put(ctx context.Context, id string, value []byte) error
}

// Renewer is one stage's renewer.
type Renewer struct {
	Name          string // turn.<stage>.vettid.org
	CertSecret    string // vettid-org/<stage>/calls/tls-cert
	AccountSecret string // vettid-org/<stage>/calls/acme-account
	// PinnedAccount is stagingCallsAcmeAccount: when set, every action but
	// register checks the stored account is that one.
	PinnedAccount string
	Secrets       Secrets
	DNS           DNS
	// ACME returns the CA's client for an account key (and its URL, once
	// registered).
	ACME    func(key crypto.Signer, accountURL string) ACME
	Roots   *x509.CertPool // nil: the system's
	Now     func() time.Time
	Metrics *metrics.Registry
	Log     *slog.Logger
	// NewKey makes a key (default ECDSA P-256).
	NewKey func() (crypto.Signer, error)
}

type stepError struct {
	step string
	err  error
}

func (e *stepError) Error() string { return e.step + ": " + e.err.Error() }

func fail(step string, err error) error { return &stepError{step: step, err: err} }

func (r *Renewer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Renewer) newKey() (crypto.Signer, error) {
	if r.NewKey != nil {
		return r.NewKey()
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Run does one action. Its metrics are put whatever the outcome (§10):
// renew{outcome} and tls_life_left of the certificate held after it.
func (r *Renewer) Run(ctx context.Context, in Input) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, Deadline)
	defer cancel()
	res := Result{Action: in.Action}
	err := r.run(ctx, in, &res)
	if err != nil {
		res.Outcome = OutcomeFailed
		var se *stepError
		if errors.As(err, &se) {
			res.Step = se.step
		} else {
			res.Step = "unknown"
		}
	}
	r.Metrics.Count("renew", metrics.Dim{Name: "outcome", Value: res.Outcome})
	life := 0.0
	if d := r.held(context.WithoutCancel(ctx)); d != nil {
		life = tlscert.LifeLeft(d.Leaf(), r.now())
		res.Serial = Serial(d.Leaf())
	}
	r.Metrics.Set("tls_life_left", "Percent", life)
	if r.Log != nil {
		attrs := []any{"action", res.Action, "outcome", res.Outcome, "account_url", res.AccountURL, "serial", res.Serial}
		if len(res.Revoked) > 0 || len(res.NotRevoked) > 0 {
			attrs = append(attrs, "revoked", res.Revoked, "not_revoked", res.NotRevoked)
		}
		if err != nil {
			// The step and the error's text, which never holds key
			// material (the adapters' errors name steps and ids only).
			r.Log.Error("calls-renewer", append(attrs, "step", res.Step, "error", err.Error())...)
		} else {
			r.Log.Info("calls-renewer", attrs...)
		}
	}
	return res, err
}

// held is the certificate secret's document when it is valid now, else
// nil.
func (r *Renewer) held(ctx context.Context) *tlscert.Doc {
	b, err := r.Secrets.Get(ctx, r.CertSecret)
	if err != nil {
		return nil
	}
	d, err := tlscert.Parse(b)
	if err != nil || d.Verify(r.Name, r.Roots, r.now()) != nil {
		return nil
	}
	return d
}

func (r *Renewer) run(ctx context.Context, in Input, res *Result) error {
	switch in.Action {
	case ActionRegister, ActionRenew, ActionForce, ActionRekey, ActionRevoke, ActionRollover:
	default:
		return fail("input", fmt.Errorf("unknown action %q", in.Action))
	}
	if in.Action != ActionRevoke && (len(in.Serials) > 0 || in.Current) {
		return fail("input", errors.New("serials and current are for revoke only"))
	}
	b, err := r.Secrets.Get(ctx, r.AccountSecret)
	if err != nil {
		return fail("account", err)
	}
	acct, err := parseAccount(b)
	if in.Action == ActionRegister {
		return r.register(ctx, acct, err, res)
	}
	if err != nil {
		return fail("account", err)
	}
	res.AccountURL = acct.URL
	if r.PinnedAccount != "" && acct.URL != r.PinnedAccount {
		return fail("account", errors.New("the stored account is not the pinned one"))
	}
	client := r.ACME(acct.Key, acct.URL)
	switch in.Action {
	case ActionRenew:
		if d := r.held(ctx); d != nil && tlscert.LifeLeft(d.Leaf(), r.now()) >= RenewAt {
			res.Outcome = OutcomeKept
			return nil
		}
		return r.issue(ctx, client, acct, res)
	case ActionForce:
		return r.issue(ctx, client, acct, res)
	case ActionRekey:
		if d := r.held(ctx); d != nil && r.Log != nil {
			// Before the put: the serial to revoke, even if what follows fails.
			r.Log.Info("calls-renewer", "action", in.Action, "replacing", Serial(d.Leaf()))
		}
		if err := r.issue(ctx, client, acct, res); err != nil {
			return err
		}
		return r.revoke(ctx, client, acct, Input{Action: ActionRevoke}, res)
	case ActionRevoke:
		return r.revoke(ctx, client, acct, in, res)
	case ActionRollover:
		k, err := r.newKey()
		if err != nil {
			return fail("rollover", err)
		}
		if err := client.Rollover(ctx, k); err != nil {
			return fail("rollover", err)
		}
		acct.Key = k
		if err := r.putAccount(ctx, acct); err != nil {
			return err
		}
		res.Outcome = OutcomeKept
		return nil
	}
	return nil
}

func (r *Renewer) register(ctx context.Context, acct *Account, perr error, res *Result) error {
	if perr == nil {
		res.AccountURL, res.Outcome = acct.URL, OutcomeKept // an account is there: nothing changes
		return nil
	}
	if !errors.Is(perr, errEmptyAccount) {
		return fail("account", perr)
	}
	k, err := r.newKey()
	if err != nil {
		return fail("register", err)
	}
	url, err := r.ACME(k, "").Register(ctx)
	if err != nil {
		return fail("register", err)
	}
	a := &Account{Key: k, URL: url}
	if err := r.putAccount(ctx, a); err != nil {
		return err
	}
	res.AccountURL, res.Outcome = url, OutcomeRegistered
	return nil
}

func (r *Renewer) putAccount(ctx context.Context, a *Account) error {
	b, err := a.marshal(r.now())
	if err != nil {
		return fail("account_put", err)
	}
	if err := r.Secrets.Put(ctx, r.AccountSecret, b); err != nil {
		return fail("account_put", err)
	}
	return nil
}

// issue gets a new certificate with a new key and puts it; the TXT record
// is deleted whatever the outcome.
func (r *Renewer) issue(ctx context.Context, client ACME, acct *Account, res *Result) error {
	order, err := client.Order(ctx, r.Name)
	if err != nil {
		return fail("order", err)
	}
	record := "_acme-challenge." + r.Name
	for _, authz := range order.Authz {
		ch, err := client.DNSChallenge(ctx, authz)
		if err != nil {
			return fail("challenge", err)
		}
		if ch.Done {
			continue
		}
		if err := r.answer(ctx, client, authz, record, ch); err != nil {
			return err
		}
	}
	key, err := r.newKey()
	if err != nil {
		return fail("key", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: r.Name}, DNSNames: []string{r.Name}}, key)
	if err != nil {
		return fail("csr", err)
	}
	ders, err := client.Finalize(ctx, order.URL, csr)
	if err != nil {
		return fail("finalize", err)
	}
	d := &tlscert.Doc{Key: key}
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fail("verify", errors.New("a certificate of the chain does not parse"))
		}
		d.Chain = append(d.Chain, c)
	}
	if len(d.Chain) == 0 {
		return fail("verify", errors.New("no certificate"))
	}
	if err := d.Verify(r.Name, r.Roots, r.now()); err != nil {
		return fail("verify", err)
	}
	b, err := d.Marshal()
	if err != nil {
		return fail("put", err)
	}
	if err := r.Secrets.Put(ctx, r.CertSecret, b); err != nil {
		return fail("put", err)
	}
	acct.Issued = append(acct.Issued, d.Leaf())
	res.Outcome = OutcomeIssued
	// The certificate is in place; a failure to record it for revoke is
	// still a failure of the run (the alarm fires), not of the issuance.
	return r.putAccount(ctx, acct)
}

func (r *Renewer) answer(ctx context.Context, client ACME, authz, record string, ch *Challenge) error {
	change, err := r.DNS.Upsert(ctx, record, ch.Record)
	defer func() {
		// Whatever the outcome, and past the run's deadline.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if derr := r.DNS.Delete(dctx, record, ch.Record); derr != nil && r.Log != nil {
			r.Log.Error("calls-renewer", "step", "dns_delete", "error", derr.Error())
		}
	}()
	if err != nil {
		return fail("dns", err)
	}
	if err := r.DNS.WaitInSync(ctx, change); err != nil {
		return fail("dns", err)
	}
	if err := client.Accept(ctx, ch); err != nil {
		return fail("challenge", err)
	}
	if err := client.WaitAuthorization(ctx, authz); err != nil {
		return fail("challenge", err)
	}
	return nil
}

// revoke revokes listed certificates (§8.5): the given serials, which
// must be listed, or every listed one but the current one. The current
// one only with in.Current. Each revoked one leaves the list.
func (r *Renewer) revoke(ctx context.Context, client ACME, acct *Account, in Input, res *Result) error {
	current := ""
	if d := r.held(ctx); d != nil {
		current = Serial(d.Leaf())
	}
	now := r.now()
	var targets []*x509.Certificate
	if len(in.Serials) > 0 {
		for _, s := range in.Serials {
			i := slices.IndexFunc(acct.Issued, func(c *x509.Certificate) bool { return Serial(c) == s })
			if i < 0 {
				return fail("revoke", fmt.Errorf("serial %s is not listed", s))
			}
			if s == current && !in.Current {
				return fail("revoke", fmt.Errorf("serial %s is the current certificate; say current to revoke it", s))
			}
			targets = append(targets, acct.Issued[i])
		}
	} else {
		for _, c := range acct.Issued {
			if Serial(c) != current && now.Before(c.NotAfter) {
				targets = append(targets, c)
			}
		}
	}
	if len(targets) == 0 {
		if res.Outcome == "" {
			res.Outcome = OutcomeKept // nothing to revoke: not a failure
		}
		return nil
	}
	var failed error
	for _, c := range targets {
		if err := client.Revoke(ctx, c.Raw); err != nil {
			res.NotRevoked = append(res.NotRevoked, Serial(c))
			failed = err
			continue
		}
		res.Revoked = append(res.Revoked, Serial(c))
		acct.Issued = slices.DeleteFunc(acct.Issued, func(x *x509.Certificate) bool { return x.Equal(c) })
	}
	if err := r.putAccount(ctx, acct); err != nil {
		return err
	}
	if failed != nil {
		return fail("revoke", failed)
	}
	if res.Outcome == "" {
		res.Outcome = OutcomeRevoked
	}
	return nil
}

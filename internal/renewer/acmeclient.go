package renewer

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
)

// LetsEncrypt is Let's Encrypt's production directory (§8.5: its
// certificates are the ones the apps' WebRTC is tested against).
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// UserAgent names the client to the CA, and nothing about who runs it.
const UserAgent = "vettid-calls-renewer"

// NewClient is the ACME adapter over golang.org/x/crypto/acme for one
// account key; accountURL is empty before registration.
func NewClient(directory string, hc *http.Client) func(key crypto.Signer, accountURL string) ACME {
	return func(key crypto.Signer, accountURL string) ACME {
		return &client{c: &acme.Client{DirectoryURL: directory, Key: key, KID: acme.KeyID(accountURL),
			UserAgent: UserAgent, HTTPClient: hc}}
	}
}

type client struct{ c *acme.Client }

func (a *client) Register(ctx context.Context) (string, error) {
	acct, err := a.c.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	if err != nil {
		return "", errors.New("registering the account failed: " + problem(err))
	}
	return acct.URI, nil
}

func (a *client) Order(ctx context.Context, name string) (*Order, error) {
	o, err := a.c.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return nil, errors.New("the order failed: " + problem(err))
	}
	return &Order{URL: o.URI, Authz: o.AuthzURLs}, nil
}

func (a *client) DNSChallenge(ctx context.Context, authzURL string) (*Challenge, error) {
	z, err := a.c.GetAuthorization(ctx, authzURL)
	if err != nil {
		return nil, errors.New("reading the authorization failed: " + problem(err))
	}
	if z.Status == acme.StatusValid {
		return &Challenge{Done: true}, nil
	}
	for _, ch := range z.Challenges {
		if ch.Type != "dns-01" {
			continue
		}
		rec, err := a.c.DNS01ChallengeRecord(ch.Token)
		if err != nil {
			return nil, errors.New("the DNS-01 record could not be made")
		}
		return &Challenge{URL: ch.URI, Token: ch.Token, Record: rec, Raw: ch}, nil
	}
	return nil, errors.New("the CA offered no dns-01 challenge")
}

func (a *client) Accept(ctx context.Context, c *Challenge) error {
	ch, ok := c.Raw.(*acme.Challenge)
	if !ok {
		return errors.New("not this client's challenge")
	}
	if _, err := a.c.Accept(ctx, ch); err != nil {
		return errors.New("accepting the challenge failed: " + problem(err))
	}
	return nil
}

func (a *client) WaitAuthorization(ctx context.Context, url string) error {
	if _, err := a.c.WaitAuthorization(ctx, url); err != nil {
		return errors.New("the authorization did not become valid: " + problem(err))
	}
	return nil
}

func (a *client) Finalize(ctx context.Context, orderURL string, csr []byte) ([][]byte, error) {
	o, err := a.c.WaitOrder(ctx, orderURL)
	if err != nil {
		return nil, errors.New("the order did not become ready: " + problem(err))
	}
	der, _, err := a.c.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	if err != nil {
		return nil, errors.New("finalizing the order failed: " + problem(err))
	}
	return der, nil
}

// Revoke revokes with the account key (the client's), reason
// keyCompromise.
func (a *client) Revoke(ctx context.Context, der []byte) error {
	if err := a.c.RevokeCert(ctx, nil, der, acme.CRLReasonKeyCompromise); err != nil {
		return errors.New("the revocation failed: " + problem(err))
	}
	return nil
}

func (a *client) Rollover(ctx context.Context, newKey crypto.Signer) error {
	if err := a.c.AccountKeyRollover(ctx, newKey); err != nil {
		return errors.New("the key rollover failed: " + problem(err))
	}
	return nil
}

// problem is the CA's problem type and status, or a fixed text: never
// anything of a request.
func problem(err error) string {
	var e *acme.Error
	if errors.As(err, &e) {
		return e.ProblemType + " (" + http.StatusText(e.StatusCode) + ")"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "the run's deadline passed"
	}
	return "no answer from the CA"
}

// HTTPClient is the CA's HTTP client: a bounded wait per call.
func HTTPClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

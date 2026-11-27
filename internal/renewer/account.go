package renewer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"time"
)

// MaxAccountDocument bounds the account secret's document: a key, a URL
// and the leaves of the certificates not yet ended (a few at a time).
const MaxAccountDocument = 32 << 10

// Account is the ACME account secret's document (CALLING-SERVICE 0.3.0
// §8.5): the account key, its URL, and the certificates this account
// issued that have not ended, so that revoke can reach one renewed away.
// The leaves are public; no certificate key is kept here.
type Account struct {
	Key    crypto.Signer
	URL    string
	Issued []*x509.Certificate
}

type accountJSON struct {
	Key    string   `json:"key"`
	URL    string   `json:"url"`
	Issued []string `json:"issued"` // PEM leaves
}

var errEmptyAccount = errors.New("renewer: no account")

// parseAccount reads the account document; {} is errEmptyAccount.
func parseAccount(b []byte) (*Account, error) {
	bad := errors.New("renewer: the account document is malformed")
	if len(b) == 0 || len(b) > MaxAccountDocument {
		return nil, bad
	}
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		return nil, bad
	}
	if string(bytes.Join(bytes.Fields(b), nil)) == "{}" {
		return nil, errEmptyAccount
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var raw accountJSON
	if err := dec.Decode(&raw); err != nil {
		return nil, bad
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, bad
	}
	blk, rest := pem.Decode([]byte(raw.Key))
	if blk == nil || blk.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, bad
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	ek, ok := k.(*ecdsa.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("renewer: the account key is not an ECDSA PKCS#8 key")
	}
	if raw.URL == "" || len(raw.URL) > 512 {
		return nil, bad
	}
	a := &Account{Key: ek, URL: raw.URL}
	for _, p := range raw.Issued {
		blk, rest := pem.Decode([]byte(p))
		if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, bad
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, bad
		}
		a.Issued = append(a.Issued, c)
	}
	return a, nil
}

// marshal returns the document, re-encoded; leaves that have ended at now
// are dropped (nothing can use them, and nothing needs revoking).
func (a *Account) marshal(now time.Time) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(a.Key)
	if err != nil {
		return nil, errors.New("renewer: the account key does not encode")
	}
	out := accountJSON{Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), URL: a.URL, Issued: []string{}}
	var kept []*x509.Certificate
	for _, c := range a.Issued {
		if now.Before(c.NotAfter) {
			kept = append(kept, c)
			out.Issued = append(out.Issued, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
		}
	}
	a.Issued = kept
	return json.Marshal(out)
}

// Serial is a certificate's serial number as revoke takes it: lower-case
// hex, no separators.
func Serial(c *x509.Certificate) string { return hex.EncodeToString(c.SerialNumber.Bytes()) }

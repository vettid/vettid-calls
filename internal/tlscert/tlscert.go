// Package tlscert is the TURN server's TLS certificate document and what
// "valid" means for it (CALLING-SERVICE 0.3.0 §8.5), for the renewer that
// writes it and for turn-agent that serves it.
//
// The document is {"key": "<PKCS#8 PEM>", "chain": "<PEM, leaf first>"};
// {} is the empty document (no certificate, or TLS taken off). The key is
// never logged and no error carries any of the document.
package tlscert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"time"
)

// MaxDocument bounds the document (a key and a chain of a few
// certificates).
const MaxDocument = 16 << 10

// ErrEmpty is the empty document, {}.
var ErrEmpty = errors.New("tlscert: no certificate")

// Doc is a parsed document.
type Doc struct {
	Key   crypto.Signer
	Chain []*x509.Certificate // the leaf first
}

// Leaf is the end-entity certificate.
func (d *Doc) Leaf() *x509.Certificate { return d.Chain[0] }

// Parse reads a document: exactly the members key and chain, or none
// (ErrEmpty). The key is PKCS#8 (ECDSA or RSA); the chain is one or more
// CERTIFICATE blocks and nothing else.
func Parse(b []byte) (*Doc, error) {
	bad := errors.New("tlscert: malformed document")
	if len(b) == 0 || len(b) > MaxDocument {
		return nil, bad
	}
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		return nil, bad // an object, not null or anything else
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var raw struct {
		Key   *string `json:"key"`
		Chain *string `json:"chain"`
	}
	if err := dec.Decode(&raw); err != nil {
		return nil, bad
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, bad
	}
	if raw.Key == nil && raw.Chain == nil {
		return nil, ErrEmpty
	}
	if raw.Key == nil || raw.Chain == nil {
		return nil, bad
	}
	kb, rest := pem.Decode([]byte(*raw.Key))
	if kb == nil || kb.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("tlscert: the key is not one PKCS#8 PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, errors.New("tlscert: the key does not parse")
	}
	var signer crypto.Signer
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		signer = k
	case *rsa.PrivateKey:
		signer = k
	default:
		return nil, errors.New("tlscert: the key is neither ECDSA nor RSA")
	}
	d := &Doc{Key: signer}
	rest = []byte(*raw.Chain)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, errors.New("tlscert: the chain holds something other than certificates")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, errors.New("tlscert: a certificate of the chain does not parse")
		}
		d.Chain = append(d.Chain, c)
	}
	if len(d.Chain) == 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("tlscert: the chain is not PEM certificates")
	}
	return d, nil
}

// Verify is "valid" (§8.5): the chain verifies against roots for name and
// server authentication at now, every intermediate is within its own
// validity, and the key matches the leaf.
func (d *Doc) Verify(name string, roots *x509.CertPool, now time.Time) error {
	leaf := d.Leaf()
	type pub interface{ Equal(crypto.PublicKey) bool }
	p, ok := d.Key.Public().(pub)
	if !ok || !p.Equal(leaf.PublicKey) {
		return errors.New("tlscert: the key does not match the certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range d.Chain[1:] {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return errors.New("tlscert: an intermediate is outside its validity")
		}
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return fmt.Errorf("tlscert: the chain does not verify for %s", name)
	}
	return nil
}

// Encode re-encodes the parsed key (PKCS#8 PEM) and chain (PEM), never
// the document's own bytes.
func (d *Doc) Encode() (key, chain []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(d.Key)
	if err != nil {
		return nil, nil, errors.New("tlscert: the key does not encode")
	}
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, c := range d.Chain {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return key, chain, nil
}

// Marshal returns the document's JSON form, re-encoded.
func (d *Doc) Marshal() ([]byte, error) {
	key, chain, err := d.Encode()
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Key   string `json:"key"`
		Chain string `json:"chain"`
	}{string(key), string(chain)})
}

// LifeLeft is the leaf's remaining validity at now, as a percentage of its
// lifetime (0 when ended).
func LifeLeft(c *x509.Certificate, now time.Time) float64 {
	total := c.NotAfter.Sub(c.NotBefore)
	left := c.NotAfter.Sub(now)
	if total <= 0 || left <= 0 {
		return 0
	}
	if left > total {
		return 100
	}
	return 100 * float64(left) / float64(total)
}

// Same reports whether two documents hold the same key and chain.
func Same(a, b *Doc) bool {
	if a == nil || b == nil {
		return a == b
	}
	type pub interface{ Equal(crypto.PublicKey) bool }
	pa, ok := a.Key.Public().(pub)
	if !ok || !pa.Equal(b.Key.Public()) || len(a.Chain) != len(b.Chain) {
		return false
	}
	for i := range a.Chain {
		if !a.Chain[i].Equal(b.Chain[i]) {
			return false
		}
	}
	return true
}

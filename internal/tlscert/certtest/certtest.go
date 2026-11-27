// Package certtest makes throwaway certificate chains for tests: a root,
// an intermediate and a leaf, all with fresh P-256 keys. Nothing here is
// used outside tests.
package certtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"time"
)

var serial atomic.Int64

// CA is a test root and intermediate.
type CA struct {
	Root, Inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

// Opts changes what Leaf makes.
type Opts struct {
	NotBefore, NotAfter time.Time        // default: an hour ago, 90 days on
	Usage               x509.ExtKeyUsage // default server auth
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func key() *ecdsa.PrivateKey { return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)) }

func sign(tpl, parent *x509.Certificate, pub, priv any) *x509.Certificate {
	tpl.SerialNumber = big.NewInt(serial.Add(1))
	return must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tpl, parent, pub, priv))))
}

// NewCA makes a root and an intermediate, valid from a year ago to a year
// on (interFrom and interTo override the intermediate's validity when not
// zero).
func NewCA(interFrom, interTo time.Time) *CA {
	now := time.Now()
	c := &CA{rootKey: key(), interKey: key()}
	rt := &x509.Certificate{Subject: pkix.Name{CommonName: "certtest root"}, NotBefore: now.AddDate(-1, 0, 0),
		NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	c.Root = sign(rt, rt, &c.rootKey.PublicKey, c.rootKey)
	if interFrom.IsZero() {
		interFrom = now.AddDate(-1, 0, 0)
	}
	if interTo.IsZero() {
		interTo = now.AddDate(1, 0, 0)
	}
	it := &x509.Certificate{Subject: pkix.Name{CommonName: "certtest intermediate"}, NotBefore: interFrom,
		NotAfter: interTo, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	c.Inter = sign(it, c.Root, &c.interKey.PublicKey, c.rootKey)
	return c
}

// Roots is a pool holding the root.
func (c *CA) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.Root)
	return p
}

// Leaf is a leaf for name, with its key.
type Leaf struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	CA   *CA
}

// Leaf makes a leaf for name signed by the intermediate.
func (c *CA) Leaf(name string, o Opts) *Leaf {
	now := time.Now()
	if o.NotBefore.IsZero() {
		o.NotBefore = now.Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = now.Add(90 * 24 * time.Hour)
	}
	if o.Usage == 0 {
		o.Usage = x509.ExtKeyUsageServerAuth
	}
	k := key()
	tpl := &x509.Certificate{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: o.NotBefore,
		NotAfter: o.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{o.Usage}}
	return &Leaf{Cert: sign(tpl, c.Inter, &k.PublicKey, c.interKey), Key: k, CA: c}
}

// KeyPEM is the leaf's key as PKCS#8 PEM.
func (l *Leaf) KeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(l.Key))})
}

// ChainPEM is the leaf and the intermediate as PEM.
func (l *Leaf) ChainPEM() []byte {
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.Cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.CA.Inter.Raw})...)
}

// Doc is the leaf as a certificate secret's document.
func (l *Leaf) Doc() []byte {
	return must(json.Marshal(map[string]string{"key": string(l.KeyPEM()), "chain": string(l.ChainPEM())}))
}

// SignCSR signs a certificate request's key and names as a leaf (a fake
// CA's finalize).
func (c *CA) SignCSR(der []byte, o Opts) *x509.Certificate {
	req := must(x509.ParseCertificateRequest(der))
	if err := req.CheckSignature(); err != nil {
		panic(err)
	}
	now := time.Now()
	if o.NotBefore.IsZero() {
		o.NotBefore = now.Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = now.Add(90 * 24 * time.Hour)
	}
	tpl := &x509.Certificate{Subject: req.Subject, DNSNames: req.DNSNames, NotBefore: o.NotBefore, NotAfter: o.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	return sign(tpl, c.Inter, req.PublicKey, c.interKey)
}

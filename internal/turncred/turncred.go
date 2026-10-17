// Package turncred makes and checks the TURN REST credentials of
// CALLING-SERVICE §5.3 and holds the shared secret's format (§8.3).
//
//	username   = <expiry> ":" <random>
//	             expiry: Unix seconds, decimal; the moment the credential stops being accepted
//	             random: 16 bytes from the issuer's random source, base64url without padding (22 characters)
//	credential = standard base64 of HMAC-SHA-1(shared secret, username)
//
// The HMAC key is the secret exactly as coturn holds it: the bytes of the
// configured string (`static-auth-secret`), which here is the base64 text
// of the secret's 32 random bytes, not the 32 bytes themselves. coturn
// 4.18.0 computes `HMAC(secret, strlen(secret))` over the username
// (src/apps/relay/userdb.c), so the issuer must key the HMAC with the same
// string or no credential would ever verify.
//
// A username names nobody: it holds a time and random bytes that the
// issuer makes and does not keep (§5.3, V8). Nothing here logs.
package turncred

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- TURN REST (coturn use-auth-secret) is HMAC-SHA-1; it gates relay use and protects no call (CALLING-SERVICE §5.3)
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// Lifetime is a credential's lifetime (D14; CALLING-SERVICE §5.3).
const Lifetime = 6 * time.Hour

// RandomBytes is the length of a username's random part.
const RandomBytes = 16

// randomLen is the base64url length of RandomBytes without padding.
var randomLen = base64.RawURLEncoding.EncodedLen(RandomBytes)

// Credential is one credential as the issuer answers it (§5.2).
type Credential struct {
	Username   string `json:"username"`
	Credential string `json:"credential"`
	Exp        int64  `json:"exp"`
}

// ErrUsername is a username that is not of the form of §5.3.
var ErrUsername = errors.New("turncred: malformed username")

// Username returns the username for expiry exp and the random part r
// (RandomBytes long).
func Username(exp int64, r []byte) (string, error) {
	if exp <= 0 || len(r) != RandomBytes {
		return "", ErrUsername
	}
	return strconv.FormatInt(exp, 10) + ":" + base64.RawURLEncoding.EncodeToString(r), nil
}

// Sign returns the credential (password) of username under secret.
func Sign(secret, username string) string {
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Make returns a fresh credential under secret, valid from now for
// lifetime, with its random part from rnd (crypto/rand when nil).
func Make(secret string, now time.Time, lifetime time.Duration, rnd io.Reader) (Credential, error) {
	if secret == "" || lifetime <= 0 {
		return Credential{}, errors.New("turncred: no secret or no lifetime")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	r := make([]byte, RandomBytes)
	if _, err := io.ReadFull(rnd, r); err != nil {
		return Credential{}, errors.New("turncred: random source failed")
	}
	exp := now.Add(lifetime).Unix()
	u, err := Username(exp, r)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Username: u, Credential: Sign(secret, u), Exp: exp}, nil
}

// ParseUsername splits a username into its expiry and random part,
// accepting only the exact form of §5.3: a positive decimal without
// leading zeros or sign, one colon, and 22 base64url characters that
// decode to 16 bytes (canonically: the unused low bits are zero).
func ParseUsername(u string) (exp int64, r []byte, err error) {
	ts, rp, ok := strings.Cut(u, ":")
	if !ok || ts == "" || len(ts) > 19 || ts[0] == '0' || len(rp) != randomLen {
		return 0, nil, ErrUsername
	}
	for i := 0; i < len(ts); i++ {
		if ts[i] < '0' || ts[i] > '9' {
			return 0, nil, ErrUsername
		}
	}
	exp, err = strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return 0, nil, ErrUsername
	}
	r, err = base64.RawURLEncoding.Strict().DecodeString(rp)
	if err != nil || len(r) != RandomBytes {
		return 0, nil, ErrUsername
	}
	return exp, r, nil
}

// Check reports whether coturn, configured with secrets, would accept
// username and credential at now: the username is well formed, its expiry
// has not passed (coturn refuses a username whose timestamp is before
// now), and the credential is the HMAC under one of the secrets. It is the
// issuer's own check of what coturn does, for tests and for callsctl.
func Check(secrets []string, username, credential string, now time.Time) bool {
	exp, _, err := ParseUsername(username)
	if err != nil || exp < now.Unix() {
		return false
	}
	ok := 0
	for _, s := range secrets {
		ok |= subtle.ConstantTimeCompare([]byte(Sign(s, username)), []byte(credential))
	}
	return ok == 1
}

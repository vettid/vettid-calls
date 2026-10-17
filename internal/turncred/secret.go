package turncred

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
)

// The shared secret's document (CALLING-SERVICE §8.3):
//
//	{ "current": "<id>", "secrets": { "<id>": "<base64 of 32 random bytes>", … } }
//
// The issuer signs with "current"; the server accepts every secret
// listed.

// SecretBytes is the length of one secret's random value.
const SecretBytes = 32

// MaxSecrets bounds the secrets of one document. Rotation keeps two for a
// day (§8.3); more than a handful means a forgotten drop.
const MaxSecrets = 8

// MaxDocument bounds the document (Secrets Manager's own limit is 64 KiB).
const MaxDocument = 4 << 10

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Set is the parsed secret document.
type Set struct {
	Current string            `json:"current"`
	Secrets map[string]string `json:"secrets"`
}

// Errors of the secret document. None carries a secret's value.
var (
	ErrSecretDocument = errors.New("turncred: malformed secret document")
	ErrUnknownID      = errors.New("turncred: no secret with that id")
	ErrDropCurrent    = errors.New("turncred: the current secret cannot be dropped; rotate first")
)

// ParseSet reads and validates a secret document: no other members, a
// current id that names a listed secret, 1 to MaxSecrets secrets, ids of
// [a-z0-9-] (at most 32, starting with a letter or digit), and every value
// standard base64 (padded) of exactly 32 bytes.
func ParseSet(b []byte) (*Set, error) {
	if len(b) == 0 || len(b) > MaxDocument {
		return nil, ErrSecretDocument
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s Set
	if err := dec.Decode(&s); err != nil {
		return nil, ErrSecretDocument
	}
	if dec.More() {
		return nil, ErrSecretDocument
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Set) validate() error {
	if len(s.Secrets) == 0 || len(s.Secrets) > MaxSecrets {
		return fmt.Errorf("%w: 1 to %d secrets are required", ErrSecretDocument, MaxSecrets)
	}
	for id, v := range s.Secrets {
		if !idRE.MatchString(id) {
			return fmt.Errorf("%w: an id is not of [a-z0-9-]", ErrSecretDocument)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(v)
		if err != nil || len(raw) != SecretBytes {
			return fmt.Errorf("%w: secret %s is not base64 of %d bytes", ErrSecretDocument, id, SecretBytes)
		}
	}
	if _, ok := s.Secrets[s.Current]; !ok {
		return fmt.Errorf("%w: current names no listed secret", ErrSecretDocument)
	}
	return nil
}

// CurrentSecret is the secret the issuer signs with.
func (s *Set) CurrentSecret() string { return s.Secrets[s.Current] }

// IDs returns the ids, the current one first and the others in order.
func (s *Set) IDs() []string {
	ids := make([]string, 0, len(s.Secrets))
	for id := range s.Secrets {
		if id != s.Current {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return append([]string{s.Current}, ids...)
}

// Ordered returns the secrets' values in the order of IDs: what the
// server is configured with.
func (s *Set) Ordered() []string {
	var out []string
	for _, id := range s.IDs() {
		out = append(out, s.Secrets[id])
	}
	return out
}

// Equal reports whether two documents hold the same secrets and current.
func (s *Set) Equal(o *Set) bool {
	if s == nil || o == nil || s.Current != o.Current || len(s.Secrets) != len(o.Secrets) {
		return s == nil && o == nil
	}
	for id, v := range s.Secrets {
		if o.Secrets[id] != v {
			return false
		}
	}
	return true
}

// Marshal returns the document as JSON (members sorted, as encoding/json
// does for maps).
func (s *Set) Marshal() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// newEntry makes an id (the UTC date and 4 random hex digits, e.g.
// 20261017-3fa9: the date tells the operator a secret's age) and a value.
func newEntry(now time.Time, rnd io.Reader) (string, string, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	b := make([]byte, SecretBytes+2)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return "", "", errors.New("turncred: random source failed")
	}
	id := now.UTC().Format("20060102") + "-" + hex.EncodeToString(b[SecretBytes:])
	return id, base64.StdEncoding.EncodeToString(b[:SecretBytes]), nil
}

// NewSet returns a document with one fresh secret, current.
func NewSet(now time.Time, rnd io.Reader) (*Set, error) {
	id, v, err := newEntry(now, rnd)
	if err != nil {
		return nil, err
	}
	return &Set{Current: id, Secrets: map[string]string{id: v}}, nil
}

// Rotate adds a fresh secret and makes it current. The previous one stays
// listed, so the server still accepts the credentials it signed; drop it
// after a day (§8.3).
func (s *Set) Rotate(now time.Time, rnd io.Reader) error {
	if len(s.Secrets) >= MaxSecrets {
		return fmt.Errorf("%w: already %d secrets; drop one first", ErrSecretDocument, MaxSecrets)
	}
	for {
		id, v, err := newEntry(now, rnd)
		if err != nil {
			return err
		}
		if _, taken := s.Secrets[id]; taken {
			continue
		}
		s.Secrets[id], s.Current = v, id
		return nil
	}
}

// Drop removes a secret that is not current.
func (s *Set) Drop(id string) error {
	if _, ok := s.Secrets[id]; !ok {
		return ErrUnknownID
	}
	if id == s.Current {
		return ErrDropCurrent
	}
	delete(s.Secrets, id)
	return nil
}

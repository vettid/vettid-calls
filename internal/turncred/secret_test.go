package turncred

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	secA = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	secB = "//////////////////////////////////////////8="
)

func TestParseSet(t *testing.T) {
	s, err := ParseSet([]byte(`{"current":"b","secrets":{"a":"` + secA + `","b":"` + secB + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.CurrentSecret() != secB || strings.Join(s.IDs(), ",") != "b,a" || strings.Join(s.Ordered(), ",") != secB+","+secA {
		t.Fatalf("%+v", s)
	}
	bad := []string{
		``, `null`, `[]`, `{}`,
		`{"current":"a","secrets":{}}`,
		`{"current":"c","secrets":{"a":"` + secA + `"}}`,                                // current not listed
		`{"current":"a","secrets":{"a":"` + secA + `"},"x":1}`,                          // unknown member
		`{"current":"a","secrets":{"a":"AQEB"}}`,                                        // 3 bytes
		`{"current":"a","secrets":{"a":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}}`, // no padding
		`{"current":"A","secrets":{"A":"` + secA + `"}}`,                                // upper-case id
		`{"current":"a","secrets":{"a":"` + secA + `"}} {}`,                             // trailing document
	}
	for _, b := range bad {
		if _, err := ParseSet([]byte(b)); !errors.Is(err, ErrSecretDocument) {
			t.Errorf("%s: %v", b, err)
		}
	}
	// No error carries a secret's value.
	_, err = ParseSet([]byte(`{"current":"a","secrets":{"a":"` + secA[:40] + `"}}`))
	if err == nil || strings.Contains(err.Error(), secA[:20]) {
		t.Fatalf("%v", err)
	}
}

func TestNewRotateDrop(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	s, err := NewSet(now, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := s.Current
	if !strings.HasPrefix(first, "20261017-") || len(first) != 13 {
		t.Fatalf("id %q", first)
	}
	if err := s.Rotate(now.Add(30*24*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if s.Current == first || len(s.Secrets) != 2 || s.IDs()[0] != s.Current {
		t.Fatalf("%+v", s.IDs())
	}
	if err := s.Drop(s.Current); !errors.Is(err, ErrDropCurrent) {
		t.Fatal(err)
	}
	if err := s.Drop("nope"); !errors.Is(err, ErrUnknownID) {
		t.Fatal(err)
	}
	if err := s.Drop(first); err != nil {
		t.Fatal(err)
	}
	b, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseSet(b)
	if err != nil || !again.Equal(s) {
		t.Fatalf("round trip: %v", err)
	}
	for len(s.Secrets) < MaxSecrets {
		if err := s.Rotate(now, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Rotate(now, nil); err == nil {
		t.Fatal("a ninth secret")
	}
}

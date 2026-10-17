package turncred

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type vector struct {
	Name            string `json:"name"`
	Secret          string `json:"secret"`
	Now             string `json:"now"`
	LifetimeSeconds int64  `json:"lifetime_seconds"`
	RandomHex       string `json:"random_hex"`
	Username        string `json:"username"`
	Credential      string `json:"credential"`
	Exp             int64  `json:"exp"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Vectors []vector }
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return doc.Vectors
}

// §5.3: the username and credential of each vector, byte for byte.
func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			now, err := time.Parse(time.RFC3339, v.Now)
			if err != nil {
				t.Fatal(err)
			}
			r, _ := hex.DecodeString(v.RandomHex)
			c, err := Make(v.Secret, now, time.Duration(v.LifetimeSeconds)*time.Second, bytes.NewReader(r))
			if err != nil {
				t.Fatal(err)
			}
			if c.Username != v.Username || c.Credential != v.Credential || c.Exp != v.Exp {
				t.Fatalf("got %+v, want %s %s %d", c, v.Username, v.Credential, v.Exp)
			}
			if !Check([]string{v.Secret}, v.Username, v.Credential, now) {
				t.Fatal("Check refuses its own vector")
			}
		})
	}
}

// §5.3's form: <expiry>:<22 base64url characters>, nothing else.
func TestUsernameFormat(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := Make("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", now, Lifetime, nil)
		if err != nil {
			t.Fatal(err)
		}
		exp, r, err := ParseUsername(c.Username)
		if err != nil || exp != now.Add(6*time.Hour).Unix() || exp != c.Exp || len(r) != 16 {
			t.Fatalf("%q: %v %d %d", c.Username, err, exp, len(r))
		}
		ts, rp, _ := strings.Cut(c.Username, ":")
		if ts != "1792260000" || len(rp) != 22 || strings.ContainsAny(rp, "+/=") {
			t.Fatalf("%q is not <expiry>:<22 base64url>", c.Username)
		}
		raw, err := base64.StdEncoding.DecodeString(c.Credential)
		if err != nil || len(raw) != 20 {
			t.Fatalf("credential %q is not standard base64 of an HMAC-SHA-1", c.Credential)
		}
		if seen[rp] {
			t.Fatal("a random part repeated")
		}
		seen[rp] = true
	}
	if Lifetime != 6*time.Hour {
		t.Fatal("D14: the lifetime is 6 hours")
	}
}

func TestParseUsernameRefuses(t *testing.T) {
	good := "1792260000:AAECAwQFBgcICQoLDA0ODw"
	if _, _, err := ParseUsername(good); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"", ":", "1792260000", "1792260000:", ":AAECAwQFBgcICQoLDA0ODw",
		"01792260000:AAECAwQFBgcICQoLDA0ODw",  // leading zero
		"+1792260000:AAECAwQFBgcICQoLDA0ODw",  // sign
		"0:AAECAwQFBgcICQoLDA0ODw",            // zero
		"17922600x0:AAECAwQFBgcICQoLDA0ODw",   // not decimal
		"1792260000:AAECAwQFBgcICQoLDA0ODw==", // padding
		"1792260000:AAECAwQFBgcICQoLDA0OD",    // 21 characters
		"1792260000:AAECAwQFBgcICQoLDA0ODx",   // non-canonical last character
		"1792260000:AAECAwQFBgcICQoLDA0OD+",   // standard alphabet
		"1792260000:AAECAwQFBgcICQoLDA0ODw:x", // a second colon
		"99999999999999999999:AAECAwQFBgcICQoLDA0ODw",
		"alice:AAECAwQFBgcICQoLDA0ODw", // a name in place of the time
	} {
		if _, _, err := ParseUsername(u); !errors.Is(err, ErrUsername) {
			t.Errorf("%q accepted", u)
		}
	}
}

// What coturn accepts: an unexpired username, the HMAC under any listed
// secret; the expiry second itself is still accepted (coturn refuses a
// timestamp before now).
func TestCheck(t *testing.T) {
	a, b := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "//////////////////////////////////////////8="
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c, err := Make(a, now, Lifetime, nil)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Unix(c.Exp, 0)
	cases := []struct {
		name    string
		secrets []string
		user    string
		cred    string
		at      time.Time
		want    bool
	}{
		{"fresh", []string{a}, c.Username, c.Credential, now, true},
		{"either secret listed", []string{b, a}, c.Username, c.Credential, now, true},
		{"at the expiry second", []string{a}, c.Username, c.Credential, exp, true},
		{"one second after", []string{a}, c.Username, c.Credential, exp.Add(time.Second), false},
		{"secret not listed", []string{b}, c.Username, c.Credential, now, false},
		{"altered username", []string{a}, strings.Replace(c.Username, "1792260000", "1792263600", 1), c.Credential, now, false},
		{"altered credential", []string{a}, c.Username, Sign(b, c.Username), now, false},
		{"no secrets", nil, c.Username, c.Credential, now, false},
	}
	for _, tc := range cases {
		if got := Check(tc.secrets, tc.user, tc.cred, tc.at); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

func TestMakeRefuses(t *testing.T) {
	now := time.Now()
	if _, err := Make("", now, Lifetime, nil); err == nil {
		t.Error("no secret")
	}
	if _, err := Make("x", now, 0, nil); err == nil {
		t.Error("no lifetime")
	}
	if _, err := Make("x", now, Lifetime, bytes.NewReader(make([]byte, 3))); err == nil {
		t.Error("short random source")
	}
}

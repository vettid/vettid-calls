package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-calls/internal/turncred"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func ctl(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb, func() time.Time { return t0 })
	return code, out.String(), errb.String()
}

// §8.3: new, rotate, drop, list, as the monthly rotation uses them.
func TestSecretLifecycle(t *testing.T) {
	code, doc, _ := ctl(t, "", "secret", "new")
	if code != 0 {
		t.Fatal("new")
	}
	s, err := turncred.ParseSet([]byte(doc))
	if err != nil || len(s.Secrets) != 1 {
		t.Fatalf("%v %s", err, doc)
	}
	first := s.Current
	code, doc2, _ := ctl(t, doc, "secret", "rotate")
	s2, _ := turncred.ParseSet([]byte(doc2))
	if code != 0 || len(s2.Secrets) != 2 || s2.Current == first || s2.Secrets[first] != s.Secrets[first] {
		t.Fatalf("rotate: %s", doc2)
	}
	code, list, _ := ctl(t, doc2, "secret", "list")
	if code != 0 || !strings.Contains(list, s2.Current+"  (current)") || !strings.Contains(list, first) {
		t.Fatalf("list: %s", list)
	}
	for _, v := range s2.Secrets {
		if strings.Contains(list, v) {
			t.Fatal("list printed a secret")
		}
	}
	if code, _, e := ctl(t, doc2, "secret", "drop", s2.Current); code == 0 || !strings.Contains(e, "rotate first") {
		t.Fatal("dropped the current secret")
	}
	code, doc3, _ := ctl(t, doc2, "secret", "drop", first)
	s3, _ := turncred.ParseSet([]byte(doc3))
	if code != 0 || len(s3.Secrets) != 1 || s3.Current != s2.Current {
		t.Fatalf("drop: %s", doc3)
	}
	if code, _, _ := ctl(t, "{}", "secret", "rotate"); code == 0 {
		t.Fatal("rotate of a malformed document")
	}
}

// §11 item 3: a test credential the server accepts, and a short one for
// exit test step 12.
func TestCredential(t *testing.T) {
	_, doc, _ := ctl(t, "", "secret", "new")
	code, out, e := ctl(t, doc, "credential", "-ttl", "5m", "-turn-host", "turn.staging.vettid.org")
	if code != 0 {
		t.Fatal(e)
	}
	var c struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
		Exp        int64    `json:"exp"`
	}
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatal(err)
	}
	if c.Exp != t0.Add(5*time.Minute).Unix() || len(c.URLs) != 3 {
		t.Fatalf("%s", out)
	}
	if code, res, _ := ctl(t, doc, "check", c.Username, c.Credential); code != 0 || strings.TrimSpace(res) != "accepted" {
		t.Fatal("check refused the test credential")
	}
	if code, _, _ := ctl(t, doc, "check", c.Username, "AAAA"); code != 1 {
		t.Fatal("check accepted a wrong credential")
	}
	if code, _, _ := ctl(t, doc, "credential", "-ttl", "7h"); code == 0 {
		t.Fatal("a 7-hour credential")
	}
	if code, _, _ := ctl(t, doc, "credential", "-turn-host", "a b"); code == 0 {
		t.Fatal("a bad host")
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"secret"}, {"secret", "drop"}, {"nope"}, {"check", "x"}} {
		if code, _, _ := ctl(t, "", args...); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
}

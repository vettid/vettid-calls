package turnsstatus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	good := map[string]Status{
		`{"verified_at":1,"not_after":2}`:                {1, 2},
		`{"not_after":2,"verified_at":1}`:                {1, 2},
		` { "verified_at" : 0 , "not_after" : 0 } `:      {},
		`{"verified_at":9007199254740992,"not_after":0}`: {1 << 53, 0},
	}
	for in, want := range good {
		got, err := Parse([]byte(in))
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	bad := []string{
		``,
		`null`,
		`[]`,
		`{}`,
		`{"verified_at":1}`,
		`{"verified_at":1,"not_after":2,"x":3}`,
		`{"verified_at":1,"verified_at":2,"not_after":3}`,
		`{"verified_at":1,"not_after":2}{}`,
		`{"verified_at":1,"not_after":2} x`,
		`{"verified_at":"1","not_after":2}`,
		`{"verified_at":1.0,"not_after":2}`,
		`{"verified_at":1e3,"not_after":2}`,
		`{"verified_at":-1,"not_after":2}`,
		`{"verified_at":9007199254740993,"not_after":2}`,
		`{"verified_at":true,"not_after":2}`,
		`{"verified_at":1,"not_after":2` + strings.Repeat(" ", MaxSize) + `}`,
	}
	for _, in := range bad {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestEncodeParses(t *testing.T) {
	s := Status{VerifiedAt: 1764250000, NotAfter: 1772000000}
	if got, err := Parse(s.Encode()); err != nil || got != s {
		t.Fatalf("%s: %+v %v", s.Encode(), got, err)
	}
	if string(Status{}.Encode()) != `{"verified_at":0,"not_after":0}` {
		t.Fatal(string(Status{}.Encode()))
	}
}

func TestFresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	end := now.Add(30 * 24 * time.Hour).Unix()
	cases := []struct {
		name string
		s    Status
		want bool
	}{
		{"just verified", Status{now.Unix(), end}, true},
		{"24 min old", Status{now.Add(-24 * time.Minute).Unix(), end}, true},
		{"25 min old", Status{now.Add(-25 * time.Minute).Unix(), end}, false},
		{"zero", Status{0, end}, false},
		{"never", Status{}, false},
		{"5 min ahead", Status{now.Add(5 * time.Minute).Unix(), end}, true},
		{"6 min ahead", Status{now.Add(6 * time.Minute).Unix(), end}, false},
		{"far future", Status{now.Add(1000 * time.Hour).Unix(), end}, false},
		{"certificate ended", Status{now.Unix(), now.Unix()}, false},
		{"certificate ends in a second", Status{now.Unix(), now.Unix() + 1}, true},
	}
	for _, c := range cases {
		if got := c.s.Fresh(now); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

type src struct {
	b     []byte
	err   error
	calls int
}

func (s *src) Get(context.Context) ([]byte, error) { s.calls++; return s.b, s.err }

func TestHolder(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	good := Status{now.Unix(), now.Add(time.Hour).Unix()}
	s := &src{b: good.Encode()}
	var reports int
	var lastMalformed bool
	h := &Holder{Source: s, Now: clock, Report: func(_ Status, m bool, _ error) { reports++; lastMalformed = m }}
	ctx := context.Background()

	if h.Get(ctx) != good || s.calls != 1 {
		t.Fatal("first read")
	}
	// Within RefreshInterval: no read.
	now = now.Add(9 * time.Minute)
	if h.Get(ctx) != good || s.calls != 1 {
		t.Fatal("read too early")
	}
	// A failed read keeps the last status (Fresh still ages it).
	now = now.Add(2 * time.Minute)
	s.err = errors.New("network")
	if h.Get(ctx) != good || s.calls != 2 {
		t.Fatal("a failed read dropped the status")
	}
	// Retried after RetryInterval, not before.
	now = now.Add(30 * time.Second)
	h.Get(ctx)
	if s.calls != 2 {
		t.Fatal("retried before RetryInterval")
	}
	now = now.Add(31 * time.Second)
	h.Get(ctx)
	if s.calls != 3 {
		t.Fatal("not retried")
	}
	// A malformed value is "not verified", not "keep".
	s.err, s.b = nil, []byte(`{"verified_at":1}`)
	now = now.Add(time.Minute)
	if h.Get(ctx) != (Status{}) || !lastMalformed {
		t.Fatal("a malformed value was kept or not reported")
	}
	// Missing is "not verified".
	s.b, s.err = good.Encode(), nil
	now = now.Add(11 * time.Minute)
	if h.Get(ctx) != good {
		t.Fatal("good again")
	}
	s.err = ErrNotFound
	now = now.Add(11 * time.Minute)
	if h.Get(ctx) != (Status{}) {
		t.Fatal("a missing status was kept")
	}
	if reports != s.calls {
		t.Fatalf("reports %d, reads %d", reports, s.calls)
	}
}

func TestHolderFirstReadFails(t *testing.T) {
	h := &Holder{Source: &src{err: errors.New("network")}}
	if h.Get(context.Background()).Fresh(time.Now()) {
		t.Fatal("verified without a read")
	}
}

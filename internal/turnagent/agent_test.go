package turnagent

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/secretsrc"
)

// An exposition in coturn 4.18.0's names, with the labels it uses.
const exposition = `# HELP turn_total_allocations Represents current allocations number
# TYPE turn_total_allocations gauge
turn_total_allocations{type="UDP"} 3
turn_total_allocations{type="TCP"} 1
# TYPE turn_auth_credential_failures counter
turn_auth_credential_failures{cause="expired"} 2
turn_auth_credential_failures{cause="integrity_mismatch"} 5
turn_auth_credential_failures{cause="not_found"} 0
stun_binding_request 40
stun_binding_response 40
turn_total_traffic_sentb 1000
turn_total_traffic_peer_sentb 500
turn_traffic_sentb{realm="turn.staging.vettid.org"} 1000
turn_total_traffic_rcvb 9999
`

func TestParseExposition(t *testing.T) {
	s, err := ParseExposition(strings.NewReader(exposition))
	if err != nil {
		t.Fatal(err)
	}
	if s.Allocations != 4 || s.AuthFailures != 7 || s.STUNBindings != 40 || s.BytesSent != 1500 {
		t.Fatalf("%+v", s)
	}
	for _, bad := range []string{"", "stun_binding_request 1\n", "turn_total_allocations{type=\"UDP\" 3\n",
		"turn_total_allocations NaN\n", "turn_total_allocations -1\n", "turn_total_allocations\n"} {
		if _, err := ParseExposition(strings.NewReader(bad)); !errors.Is(err, ErrExposition) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDelta(t *testing.T) {
	if delta(10, 15) != 5 || delta(10, 3) != 3 || delta(0, 0) != 0 {
		t.Fatal("delta")
	}
}

// Refusals are counted from coturn's log lines, which are dropped.
func TestLogCounter(t *testing.T) {
	alloc := 10.0
	c := &LogCounter{TotalQuota: 100, Allocations: func() float64 { return alloc }}
	pre := "1729166400: : session 001000000000000001: realm <turn.staging.vettid.org> user <1792260000:AAECAwQFBgcICQoLDA0ODw>: "
	lines := pre + "incoming packet ALLOCATE processed, error 486: Allocation Quota Reached (session 001000000000000001)\n" +
		pre + "incoming packet ALLOCATE processed, error 486: Allocation Bandwidth Quota Reached (session 1)\n" +
		pre + "incoming packet ALLOCATE processed, error 508: Cannot create socket (session 1)\n" +
		pre + "incoming packet ALLOCATE processed, success (session 1)\n" +
		pre + "incoming packet REFRESH processed, error 486: Allocation Quota Reached (session 1)\n" +
		pre + "incoming packet ALLOCATE processed, error 401: Unauthorized (session 1)\n"
	c.Consume(strings.NewReader(lines))
	got := c.Take()
	if got[RefusedQuotaUser] != 1 || got[RefusedCapacity] != 2 || got[RefusedQuotaTotal] != 0 || len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if len(c.Take()) != 0 {
		t.Fatal("not reset")
	}
	alloc = 100
	c.Line(pre + "incoming packet ALLOCATE processed, error 486: Allocation Quota Reached (session 2)")
	if c.Take()[RefusedQuotaTotal] != 1 {
		t.Fatal("quota_total")
	}
}

// Every 508 and 486 text coturn 4.18.0 can write for an ALLOCATE, in both
// of log_method's formats (with and without an origin): only the ones
// that mean the server is full are counted.
func TestLogCounterTexts(t *testing.T) {
	c := &LogCounter{TotalQuota: 100, Allocations: func() float64 { return 3 }}
	for _, pre := range []string{
		"1729166400: : session 001000000000000001: realm <turn.staging.vettid.org> user <1792260000:AAECAwQFBgcICQoLDA0ODw>: ",
		"1729166400: : session 001000000000000001: origin <https://example.org> realm <turn.staging.vettid.org> user <1792260000:AAECAwQFBgcICQoLDA0ODw>: ",
	} {
		for text, want := range map[string]string{
			"486: Allocation Quota Reached":                                                "quota_user",
			"486: Allocation Bandwidth Quota Reached":                                      "capacity",
			"508: Cannot create socket":                                                    "capacity",
			"508: Cannot create relay socket":                                              "capacity",
			"508: Insufficient Capacity":                                                   "capacity",
			"508: Dual allocation cannot be supported in the current server configuration": "",
			"508: Cannot find reserved socket":                                             "",
			"508: EVEN-PORT is not supported with multiplex-peer":                          "",
			"486: Allocation Quota Reached, but not quite":                                 "",
			"440: Unsupported address family":                                              "",
			"400: Bad Request":                                                             "",
			"437: Allocation Mismatch":                                                     "",
		} {
			c.Line(pre + "incoming packet ALLOCATE processed, error " + text + " (session 001000000000000001)\n")
			got := c.Take()
			if want == "" && len(got) != 0 || want != "" && (len(got) != 1 || got[want] != 1) {
				t.Errorf("%q: %v, want %q", text, got, want)
			}
		}
	}
}

// A line too long to look at is skipped without stopping the count, and
// the reader is read to its end.
func TestLogCounterLongLine(t *testing.T) {
	c := &LogCounter{}
	refusal := "x: incoming packet ALLOCATE processed, error 508: Cannot create socket (session 1)"
	long := strings.Repeat("a", 3*maxLogLine) + refusal + "\n"               // not counted: past the limit
	r := strings.NewReader(refusal + "\n" + long + refusal + "\n" + refusal) // the last has no newline
	c.Consume(r)
	if got := c.Take(); got[RefusedCapacity] != 3 || len(got) != 1 {
		t.Fatalf("%v", got)
	}
	if r.Len() != 0 {
		t.Fatal("not read to the end")
	}
}

type fakeProc struct {
	done chan struct{}
	once sync.Once
	sigs []os.Signal
	mu   sync.Mutex
}

func (p *fakeProc) Wait() error { <-p.done; return nil }
func (p *fakeProc) Signal(s os.Signal) error {
	p.mu.Lock()
	p.sigs = append(p.sigs, s)
	p.mu.Unlock()
	p.once.Do(func() { close(p.done) })
	return nil
}
func (p *fakeProc) exit() { p.once.Do(func() { close(p.done) }) }

type mutableSource struct {
	mu  sync.Mutex
	doc string
}

func (m *mutableSource) Get(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return []byte(m.doc), nil
}

func (m *mutableSource) set(doc string) { m.mu.Lock(); m.doc = doc; m.mu.Unlock() }

// The agent end to end with a fake coturn: the configuration on disk
// (0600), the counters per interval, a restart when the secret changes
// and when coturn exits, and coturn stopped at the end.
func TestAgent(t *testing.T) {
	dir := t.TempDir()
	p := params()
	p.RunDir, p.Secrets = dir, nil
	src := &mutableSource{doc: `{"current":"a","secrets":{"a":"` + secA + `"}}`}
	var mu sync.Mutex
	clock := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }

	var procs []*fakeProc
	var confs []string
	started := make(chan struct{}, 10)
	rec := &metrics.Recorder{}
	reported := make(chan struct{}, 100)
	a := &Agent{
		Params:  p,
		Secrets: &secretsrc.Holder{Source: src, Now: now},
		Metrics: metrics.New("test", nil),
		Sink:    sinkFunc(func(d []metrics.Datum) { _ = rec.Put(context.Background(), "", time.Time{}, d); reported <- struct{}{} }),
		Start: func(conf string, out io.Writer) (Process, error) {
			b, err := os.ReadFile(conf)
			if err != nil {
				return nil, err
			}
			st, _ := os.Stat(conf)
			if st.Mode().Perm() != 0o600 {
				t.Errorf("configuration mode %v", st.Mode().Perm())
			}
			_, _ = io.WriteString(out, "realm <x> user <1:y>: incoming packet ALLOCATE processed, error 486: Allocation Bandwidth Quota Reached (session 1)\n")
			mu.Lock()
			pr := &fakeProc{done: make(chan struct{})}
			procs = append(procs, pr)
			confs = append(confs, string(b))
			mu.Unlock()
			started <- struct{}{}
			return pr, nil
		},
		Scrape:       func(context.Context) (Scrape, error) { return ParseExposition(strings.NewReader(exposition)) },
		Interval:     20 * time.Millisecond,
		RestartDelay: time.Millisecond,
		StopTimeout:  time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	<-started
	<-reported
	<-reported

	// The secret changes: read again after 10 minutes, coturn restarted
	// with both secrets, the new one first.
	src.set(`{"current":"b","secrets":{"a":"` + secA + `","b":"` + secB + `"}}`)
	advance(11 * time.Minute)
	<-started
	mu.Lock()
	if len(procs) != 2 || len(procs[0].sigs) == 0 {
		t.Fatal("coturn was not stopped for the new secret")
	}
	if !strings.Contains(confs[1], "static-auth-secret="+secB+"\nstatic-auth-secret="+secA) {
		t.Fatalf("second configuration:\n%s", confs[1])
	}
	last := procs[1]
	mu.Unlock()

	// coturn exits by itself: started again.
	last.exit()
	<-started
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if n := len(procs[2].sigs); n == 0 {
		t.Fatal("coturn was not stopped at the end")
	}
	mu.Unlock()

	sum := map[string]float64{}
	for _, batch := range rec.Data {
		for _, d := range batch {
			k := d.Name
			for _, dm := range d.Dims {
				k += "{" + dm.Value + "}"
			}
			if d.Gauge {
				sum[k] = d.Value
			} else {
				sum[k] += d.Value
			}
		}
	}
	if sum["heartbeat"] < 2 || sum["allocations"] != 4 || sum["allocations_refused{capacity}"] < 1 ||
		sum["coturn_restarts{secret}"] != 1 || sum["coturn_restarts{exit}"] != 1 || sum["agent_errors{exit}"] != 1 {
		t.Fatalf("%v", sum)
	}
	// The counters' deltas are zero while coturn's values do not move.
	if sum["auth_failures"] != 0 || sum["bytes_relayed"] != 0 {
		t.Fatalf("%v", sum)
	}
	// No dimension holds anything but a closed-set value.
	for k := range sum {
		if strings.Contains(k, "turn.staging") || strings.Contains(k, ":") {
			t.Fatalf("dimension %s", k)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ConfName)); err != nil {
		t.Fatal(err)
	}
}

type sinkFunc func([]metrics.Datum)

func (f sinkFunc) Put(_ context.Context, _ string, _ time.Time, d []metrics.Datum) error {
	f(d)
	return nil
}

package turnagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vettid/vettid-calls/internal/metrics"
	"github.com/vettid/vettid-calls/internal/secretsrc"
	"github.com/vettid/vettid-calls/internal/turncred"
)

// ConfName is the rendered configuration's file name in the run
// directory.
const ConfName = "turnserver.conf"

// Process is a running coturn.
type Process interface {
	Wait() error
	Signal(os.Signal) error
}

// Starter starts coturn with the configuration at conf; its standard
// output and error go to out.
type Starter func(conf string, out io.Writer) (Process, error)

// ExecStarter runs the turnserver binary at path.
func ExecStarter(path string) Starter {
	return func(conf string, out io.Writer) (Process, error) {
		cmd := exec.Command(path, "-c", conf)
		cmd.Stdout, cmd.Stderr = out, out
		cmd.Env = []string{} // nothing of turn-agent's environment
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return execProcess{cmd}, nil
	}
}

type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Wait() error              { return p.cmd.Wait() }
func (p execProcess) Signal(s os.Signal) error { return p.cmd.Process.Signal(s) }

// HTTPScraper reads coturn's exposition from 127.0.0.1:port.
func HTTPScraper(port int) func(context.Context) (Scrape, error) {
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/metrics"
	hc := &http.Client{Timeout: 5 * time.Second}
	return func(ctx context.Context) (Scrape, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return Scrape{}, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return Scrape{}, errors.New("turnagent: coturn's counters are not reachable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return Scrape{}, fmt.Errorf("turnagent: coturn's counters answered %d", resp.StatusCode)
		}
		return ParseExposition(resp.Body)
	}
}

// Agent renders coturn's configuration, runs coturn and reports its
// counters once per Interval (§10).
type Agent struct {
	// Params, without Secrets: those come from Secrets.
	Params  Params
	Secrets *secretsrc.Holder
	Metrics *metrics.Registry
	Sink    metrics.Sink
	Start   Starter
	Scrape  func(context.Context) (Scrape, error)
	// Interval between reports (default one minute).
	Interval time.Duration
	// RestartDelay after coturn exits by itself (default 5 s).
	RestartDelay time.Duration
	// StopTimeout is how long coturn may take to stop before it is
	// killed (default 10 s).
	StopTimeout time.Duration
	Log         *slog.Logger

	logs      LogCounter
	mu        sync.Mutex
	lastAlloc float64
	prev      *Scrape
}

func (a *Agent) dims(name, value string) metrics.Dim { return metrics.Dim{Name: name, Value: value} }

func (a *Agent) fail(kind string, err error) {
	a.Metrics.Count("agent_errors", a.dims("kind", kind))
	if a.Log != nil {
		// Errors of turn-agent only; nothing of coturn's log.
		a.Log.Error("turn-agent", "kind", kind, "error", err.Error())
	}
}

// writeConf renders the configuration for set into the run directory,
// readable by this user only.
func (a *Agent) writeConf(set *turncred.Set) (string, error) {
	p := a.Params
	p.Secrets = set.Ordered()
	b, err := Render(p)
	if err != nil {
		return "", err
	}
	path := filepath.Join(p.RunDir, ConfName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", errors.New("turnagent: writing the configuration failed")
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", errors.New("turnagent: writing the configuration failed")
	}
	return path, nil
}

type running struct {
	proc Process
	done chan struct{}
	pw   *io.PipeWriter
}

func (a *Agent) start(conf string) (*running, error) {
	pr, pw := io.Pipe()
	go a.logs.Consume(pr)
	proc, err := a.Start(conf, pw)
	if err != nil {
		pw.Close()
		return nil, err
	}
	r := &running{proc: proc, done: make(chan struct{}), pw: pw}
	go func() {
		_ = proc.Wait()
		pw.Close()
		close(r.done)
	}()
	return r, nil
}

func (a *Agent) stop(r *running) {
	if r == nil {
		return
	}
	_ = r.proc.Signal(syscall.SIGTERM)
	t := time.NewTimer(a.StopTimeout)
	defer t.Stop()
	select {
	case <-r.done:
	case <-t.C:
		_ = r.proc.Signal(syscall.SIGKILL)
		<-r.done
	}
}

// Run runs until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	if a.Interval <= 0 {
		a.Interval = time.Minute
	}
	if a.RestartDelay <= 0 {
		a.RestartDelay = 5 * time.Second
	}
	if a.StopTimeout <= 0 {
		a.StopTimeout = 10 * time.Second
	}
	a.logs.TotalQuota = orDefault(a.Params.TotalQuota, DefaultTotalQuota)
	a.logs.Allocations = func() float64 { a.mu.Lock(); defer a.mu.Unlock(); return a.lastAlloc }

	tick := time.NewTicker(a.Interval)
	defer tick.Stop()
	var cur *running
	var restartAt time.Time
	defer func() { a.stop(cur) }()

	ensure := func(reason string) {
		set := a.Secrets.Get(ctx)
		if set == nil {
			a.fail("secret", errors.New("no TURN secret yet"))
			return
		}
		conf, err := a.writeConf(set)
		if err != nil {
			a.fail("config", err)
			return
		}
		if cur, err = a.start(conf); err != nil {
			a.fail("start", err)
			cur = nil
			return
		}
		if reason != "" {
			a.Metrics.Count("coturn_restarts", a.dims("reason", reason))
		}
	}
	ensure("")
	for {
		var done chan struct{}
		if cur != nil {
			done = cur.done
		}
		select {
		case <-ctx.Done():
			a.report(ctx, cur != nil)
			return nil
		case <-done:
			cur = nil
			a.fail("exit", errors.New("coturn exited"))
			// Started again at the first tick RestartDelay from now.
			restartAt = time.Now().Add(a.RestartDelay)
		case <-tick.C:
			if cur == nil && !time.Now().Before(restartAt) {
				ensure("exit")
			} else if cur != nil {
				_ = a.Secrets.Get(ctx) // read again when 10 minutes old (§8.3)
				if a.Secrets.Changed() {
					// coturn 4.18.0 reads its secrets only at start
					// (SIGUSR2 reloads TLS certificates only): a change
					// ends the calls being relayed (§8.3 accepts that on
					// staging).
					a.stop(cur)
					cur = nil
					ensure("secret")
				}
			}
			a.report(ctx, cur != nil)
		}
	}
}

// report scrapes coturn and puts one interval's metrics.
func (a *Agent) report(ctx context.Context, up bool) {
	if up && a.Scrape != nil && ctx.Err() == nil {
		s, err := a.Scrape(ctx)
		if err != nil {
			a.fail("scrape", err)
		} else {
			a.mu.Lock()
			a.lastAlloc = s.Allocations
			prev := a.prev
			a.prev = &s
			a.mu.Unlock()
			a.Metrics.Set("allocations", "Count", s.Allocations)
			if prev != nil {
				a.Metrics.Add("auth_failures", "Count", delta(prev.AuthFailures, s.AuthFailures))
				a.Metrics.Add("stun_bindings", "Count", delta(prev.STUNBindings, s.STUNBindings))
				a.Metrics.Add("bytes_relayed", "Bytes", delta(prev.BytesSent, s.BytesSent))
			}
			a.Metrics.Count("heartbeat")
		}
	}
	refused := a.logs.Take()
	for _, reason := range []string{RefusedQuotaUser, RefusedQuotaTotal, RefusedCapacity} {
		if n := refused[reason]; n > 0 {
			a.Metrics.Add("allocations_refused", "Count", n, a.dims("reason", reason))
		}
	}
	// Not ctx: the last report is made while ctx ends.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := metrics.Flush(fctx, a.Metrics, a.Sink); err != nil {
		a.fail("metrics", err)
	}
}

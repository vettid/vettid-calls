package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/vettid/vettid-calls/internal/config"
	"github.com/vettid/vettid-calls/internal/issuer"
	"github.com/vettid/vettid-calls/internal/turnsstatus"
)

type failing struct{}

func (failing) Get(context.Context) ([]byte, error) { return nil, errors.New("network") }

// oneLambdaRequest runs the binary in Lambda mode with d, makes one valid
// request and returns its TURN URLs and the metrics put, summed by
// name{dim}.
func oneLambdaRequest(t *testing.T, f *fixture, d deps) (string, map[string]float64) {
	t.Helper()
	f.env["AWS_LAMBDA_RUNTIME_API"] = "127.0.0.1:9001"
	f.env["AWS_REGION"] = "us-east-1"
	cfg, err := config.Load(f.lookup, false)
	if err != nil {
		t.Fatal(err)
	}
	var handler func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error)
	d.lambdaStart = func(h any) {
		handler = h.(func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error))
	}
	if err := run(context.Background(), cfg, d); err != nil {
		t.Fatal(err)
	}
	h, body := f.signed(1)
	ev := events.LambdaFunctionURLRequest{RawPath: issuer.PathCredentials, Body: string(body), Headers: map[string]string{}}
	ev.RequestContext.HTTP.Method = http.MethodPost
	for k := range h {
		ev.Headers[strings.ToLower(k)] = h.Get(k)
	}
	resp, err := handler(context.Background(), ev)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %d %s", err, resp.StatusCode, resp.Body)
	}
	var a issuer.Answer
	if err := json.Unmarshal([]byte(resp.Body), &a); err != nil {
		t.Fatal(err)
	}
	sum := map[string]float64{}
	for _, batch := range f.rec.Data {
		for _, dt := range batch {
			k := dt.Name
			for _, dm := range dt.Dims {
				k += "{" + dm.Value + "}"
			}
			sum[k] += dt.Value
		}
	}
	return strings.Join(a.TURN, ","), sum
}

const turnsURL = "turns:turn.staging.vettid.org:443?transport=tcp"

func fresh() []byte {
	now := time.Now()
	return turnsstatus.Status{VerifiedAt: now.Unix(), NotAfter: now.Add(30 * 24 * time.Hour).Unix()}.Encode()
}

// The status wired through run (CALLING-SERVICE 0.3.0 §8.5): fresh lists
// turns:, a failing read does not and says so, and with neither variable
// nothing of it is there.
func TestTURNSWiring(t *testing.T) {
	t.Run("fresh", func(t *testing.T) {
		f := newFixture(t)
		d := f.deps()
		d.turnsStatus = turnsstatus.Static(fresh())
		urls, m := oneLambdaRequest(t, f, d)
		if !strings.HasSuffix(urls, ","+turnsURL) || m["turns_listed"] != 1 || m["turns_status_refresh{ok}"] != 1 {
			t.Fatalf("%s %v", urls, m)
		}
		if _, ok := m["turns_status_age"]; !ok {
			t.Fatal("no turns_status_age")
		}
	})
	t.Run("file", func(t *testing.T) {
		f := newFixture(t)
		p := filepath.Join(t.TempDir(), "turns-status.json")
		if err := os.WriteFile(p, fresh(), 0o600); err != nil {
			t.Fatal(err)
		}
		f.env["CALLS_TURNS_STATUS_FILE"] = p
		urls, m := oneLambdaRequest(t, f, f.deps())
		if !strings.HasSuffix(urls, ","+turnsURL) || m["turns_listed"] != 1 {
			t.Fatalf("%s %v", urls, m)
		}
	})
	t.Run("failing", func(t *testing.T) {
		f := newFixture(t)
		d := f.deps()
		d.turnsStatus = failing{}
		urls, m := oneLambdaRequest(t, f, d)
		if strings.Contains(urls, "turns:") || m["turns_listed"] != 0 || m["turns_status_refresh{error}"] < 1 {
			t.Fatalf("%s %v", urls, m)
		}
		if !strings.Contains(f.logs.String(), "turns_status_error") {
			t.Fatalf("not logged:\n%s", f.logs.String())
		}
	})
	t.Run("missing", func(t *testing.T) {
		f := newFixture(t)
		f.env["CALLS_TURNS_STATUS_FILE"] = filepath.Join(t.TempDir(), "absent.json")
		urls, m := oneLambdaRequest(t, f, f.deps())
		if strings.Contains(urls, "turns:") || m["turns_status_refresh{missing}"] < 1 ||
			!strings.Contains(f.logs.String(), "turns_status_missing") {
			t.Fatalf("%s %v\n%s", urls, m, f.logs.String())
		}
	})
	t.Run("off", func(t *testing.T) {
		f := newFixture(t)
		urls, m := oneLambdaRequest(t, f, f.deps())
		if strings.Contains(urls, "turns:") {
			t.Fatal(urls)
		}
		for k := range m {
			if strings.HasPrefix(k, "turns_") {
				t.Fatalf("%s put while TLS is off", k)
			}
		}
	})
}

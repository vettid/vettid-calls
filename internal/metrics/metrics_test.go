package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRegistry(t *testing.T) {
	ts := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	r := New("vettid-org/staging/calls", func() time.Time { return ts })
	r.Count("requests", Dim{"outcome", "ok"})
	r.Count("requests", Dim{"outcome", "ok"})
	r.Count("requests", Dim{"outcome", "attestation_invalid"})
	r.Add("bytes_relayed", "Bytes", 1500)
	r.Set("allocations", "Count", 3)
	r.Set("allocations", "Count", 2)
	if r.Value("requests", Dim{"outcome", "ok"}) != 2 || r.Value("allocations") != 2 {
		t.Fatal("aggregation")
	}
	var buf bytes.Buffer
	if err := r.Flush(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines:\n%s", len(lines), buf.String())
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &doc); err != nil {
		t.Fatal(err)
	}
	aws := doc["_aws"].(map[string]any)
	if aws["Timestamp"].(float64) != float64(ts.UnixMilli()) {
		t.Fatal("timestamp")
	}
	// Flushed means reset.
	buf.Reset()
	_ = r.Flush(&buf)
	if buf.Len() != 0 {
		t.Fatal("not reset")
	}
}

func TestFlushToSink(t *testing.T) {
	r := New("ns", nil)
	var rec Recorder
	if err := Flush(context.Background(), r, &rec); err != nil || len(rec.Data) != 0 {
		t.Fatal("an empty interval is not put")
	}
	r.Count("heartbeat")
	_ = Flush(context.Background(), r, &rec)
	if len(rec.Data) != 1 || rec.Data[0][0].Name != "heartbeat" || rec.Data[0][0].Value != 1 {
		t.Fatalf("%+v", rec.Data)
	}
}

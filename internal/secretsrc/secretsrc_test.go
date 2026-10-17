package secretsrc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const docA = `{"current":"a","secrets":{"a":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}}`
const docB = `{"current":"b","secrets":{"a":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","b":"//////////////////////////////////////////8="}}`

type counting struct {
	mu   sync.Mutex
	doc  string
	err  error
	gets int
}

func (c *counting) Get(context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	return []byte(c.doc), c.err
}

// §8.3: read at start and again every 10 minutes (wall clock); the last
// good document stays when a read fails; a change is reported once.
func TestHolder(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	src := &counting{doc: docA}
	var reports []error
	h := &Holder{Source: src, Now: func() time.Time { return now }, Report: func(err error) { reports = append(reports, err) }}
	if s := h.Get(context.Background()); s == nil || s.Current != "a" {
		t.Fatal("first read")
	}
	h.Get(context.Background())
	now = now.Add(9 * time.Minute)
	h.Get(context.Background())
	if src.gets != 1 || h.Changed() {
		t.Fatalf("%d reads", src.gets)
	}
	src.err = errors.New("down")
	now = now.Add(2 * time.Minute)
	if s := h.Get(context.Background()); s == nil || s.Current != "a" {
		t.Fatal("the last good document was not kept")
	}
	h.Get(context.Background()) // within a minute of the failure: no read
	if src.gets != 2 {
		t.Fatalf("%d reads", src.gets)
	}
	src.err, src.doc = nil, docB
	now = now.Add(time.Minute)
	if s := h.Get(context.Background()); s.Current != "b" || !h.Changed() || h.Changed() {
		t.Fatal("the change")
	}
	if len(reports) != 3 || reports[1] == nil || strings.Contains(reports[1].Error(), "AQEB") {
		t.Fatalf("%v", reports)
	}
	// A malformed document is a failed read.
	src.doc = `{"current":"x"}`
	now = now.Add(11 * time.Minute)
	if s := h.Get(context.Background()); s.Current != "b" {
		t.Fatal("a malformed document replaced a good one")
	}
}

func TestSources(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "turn-secret.json")
	if _, err := File(p).Get(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	_ = os.WriteFile(p, []byte(docA), 0o600)
	if b, err := File(p).Get(context.Background()); err != nil || string(b) != docA {
		t.Fatal(err)
	}
	e := Env{Name: "X", Lookup: func(string) (string, bool) { return "", false }}
	if _, err := e.Get(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

package metrics

import (
	"context"
	"io"
	"sync"
	"time"
)

// Sink receives one interval's data.
type Sink interface {
	Put(ctx context.Context, namespace string, ts time.Time, data []Datum) error
}

// EMF writes data as embedded-metric-format lines (a self-hosted issuer
// on a platform that extracts EMF from its standard output).
type EMF struct {
	mu sync.Mutex
	W  io.Writer
}

// Put implements Sink.
func (e *EMF) Put(_ context.Context, namespace string, ts time.Time, data []Datum) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return WriteEMF(e.W, namespace, ts, data)
}

// Discard drops everything (metrics off).
type Discard struct{}

// Put implements Sink.
func (Discard) Put(context.Context, string, time.Time, []Datum) error { return nil }

// Recorder keeps what it is given (tests).
type Recorder struct {
	mu   sync.Mutex
	Data [][]Datum
}

// Put implements Sink.
func (r *Recorder) Put(_ context.Context, _ string, _ time.Time, data []Datum) error {
	r.mu.Lock()
	r.Data = append(r.Data, append([]Datum(nil), data...))
	r.mu.Unlock()
	return nil
}

// Flush takes the registry's data and puts it into sink, if any.
func Flush(ctx context.Context, r *Registry, sink Sink) error {
	ts, data := r.Take()
	if len(data) == 0 {
		return nil
	}
	return sink.Put(ctx, r.namespace, ts, data)
}

// Package metrics aggregates counters and gauges in memory and hands
// them out once per interval (CALLING-SERVICE §10: counters only).
//
// Nothing here is per request: a datum carries the count of a whole
// interval. Dimension values come from closed sets fixed in the code
// (outcome, reason); no dimension can hold an address, a username, a key
// or a request. Adapted from vettid/vettid-push internal/metrics (commit
// 7dda46f5f8f7, AGPL-3.0-or-later): the EMF rendering is the same; the
// distributions are dropped and gauges and a snapshot for CloudWatch's
// PutMetricData are added.
package metrics

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Dim is one dimension.
type Dim struct{ Name, Value string }

// Datum is one metric value of an interval.
type Datum struct {
	Name  string
	Unit  string // "Count", "Bytes" or "None"
	Dims  []Dim
	Value float64
	// Gauge: the last value set, not a sum.
	Gauge bool
}

// Registry aggregates metrics between flushes.
type Registry struct {
	namespace string
	now       func() time.Time

	mu     sync.Mutex
	series map[string]*Datum
}

// New returns a registry that reports in namespace.
func New(namespace string, now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{namespace: namespace, now: now, series: map[string]*Datum{}}
}

// Namespace is the registry's namespace.
func (r *Registry) Namespace() string { return r.namespace }

func key(name string, dims []Dim) string {
	var b strings.Builder
	b.WriteString(name)
	for _, d := range dims {
		b.WriteByte(0)
		b.WriteString(d.Name)
		b.WriteByte('=')
		b.WriteString(d.Value)
	}
	return b.String()
}

func (r *Registry) get(name, unit string, gauge bool, dims []Dim) *Datum {
	k := key(name, dims)
	d, ok := r.series[k]
	if !ok {
		d = &Datum{Name: name, Unit: unit, Dims: append([]Dim(nil), dims...), Gauge: gauge}
		r.series[k] = d
	}
	return d
}

// Count adds one to the counter name with dims.
func (r *Registry) Count(name string, dims ...Dim) { r.Add(name, "Count", 1, dims...) }

// Add adds v to the counter name (unit "Count" or "Bytes").
func (r *Registry) Add(name, unit string, v float64, dims ...Dim) {
	r.mu.Lock()
	r.get(name, unit, false, dims).Value += v
	r.mu.Unlock()
}

// Set sets the gauge name to v.
func (r *Registry) Set(name, unit string, v float64, dims ...Dim) {
	r.mu.Lock()
	r.get(name, unit, true, dims).Value = v
	r.mu.Unlock()
}

// Value returns the metric's value since the last flush (tests).
func (r *Registry) Value(name string, dims ...Dim) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d, ok := r.series[key(name, dims)]; ok {
		return d.Value
	}
	return 0
}

// Take returns every datum since the last call, sorted, and resets them.
func (r *Registry) Take() (time.Time, []Datum) {
	r.mu.Lock()
	cur := r.series
	r.series = map[string]*Datum{}
	ts := r.now()
	r.mu.Unlock()
	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Datum, 0, len(keys))
	for _, k := range keys {
		out = append(out, *cur[k])
	}
	return ts, out
}

// Flush writes one CloudWatch embedded-metric-format (EMF) line per datum
// since the last flush and resets them.
func (r *Registry) Flush(w io.Writer) error {
	ts, data := r.Take()
	return WriteEMF(w, r.namespace, ts, data)
}

// WriteEMF renders data as EMF lines.
func WriteEMF(w io.Writer, namespace string, ts time.Time, data []Datum) error {
	var out []byte
	for _, d := range data {
		names := make([]string, len(d.Dims))
		doc := map[string]any{}
		for i, dim := range d.Dims {
			names[i] = dim.Name
			doc[dim.Name] = dim.Value
		}
		doc["_aws"] = map[string]any{
			"Timestamp": ts.UnixMilli(),
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  namespace,
				"Dimensions": [][]string{names},
				"Metrics":    []any{map[string]string{"Name": d.Name, "Unit": d.Unit}},
			}},
		}
		doc[d.Name] = d.Value
		b, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		out = append(append(out, b...), '\n')
	}
	if len(out) == 0 {
		return nil
	}
	_, err := w.Write(out)
	return err
}

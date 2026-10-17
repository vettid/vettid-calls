package turnagent

import (
	"bufio"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
)

// Prometheus metric names of coturn 4.18.0 (src/apps/relay/prom_server.c).
// turn-agent reads them on the loopback interface. coturn is never given
// prometheus-username-labels, so no series carries a username; the only
// labels are realm, type and cause.
const (
	promAllocations  = "turn_total_allocations"        // gauge, by type
	promAuthFailures = "turn_auth_credential_failures" // counter, by cause
	promSTUN         = "stun_binding_request"          // counter
	promSentClient   = "turn_total_traffic_sentb"      // counter: bytes sent to clients, finished sessions
	promSentPeer     = "turn_total_traffic_peer_sentb" // counter: bytes sent to peers, finished sessions
)

// Scrape is the values turn-agent takes from one Prometheus exposition.
type Scrape struct {
	Allocations  float64
	AuthFailures float64
	STUNBindings float64
	BytesSent    float64
}

// ErrExposition is a scrape that does not parse or lacks coturn's series.
var ErrExposition = errors.New("turnagent: not a coturn exposition")

// ParseExposition reads the Prometheus text format and sums the series
// turn-agent uses. Lines it does not need are skipped; their labels are
// never kept.
func ParseExposition(r io.Reader) (Scrape, error) {
	var s Scrape
	seen := false
	sc := bufio.NewScanner(io.LimitReader(r, 4<<20))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		var dst *float64
		switch name {
		case promAllocations:
			dst = &s.Allocations
		case promAuthFailures:
			dst = &s.AuthFailures
		case promSTUN:
			dst = &s.STUNBindings
		case promSentClient, promSentPeer:
			dst = &s.BytesSent
		default:
			continue
		}
		// The value follows the labels: "name{...} value [timestamp]".
		rest := line[len(name):]
		if strings.HasPrefix(rest, "{") {
			j := strings.LastIndexByte(rest, '}')
			if j < 0 {
				return Scrape{}, ErrExposition
			}
			rest = rest[j+1:]
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			return Scrape{}, ErrExposition
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return Scrape{}, ErrExposition
		}
		*dst += v
		if name == promAllocations {
			seen = true
		}
	}
	if err := sc.Err(); err != nil {
		return Scrape{}, ErrExposition
	}
	if !seen {
		return Scrape{}, ErrExposition
	}
	return s, nil
}

// delta is a counter's growth since prev; a counter that went down was
// reset (coturn restarted), and then all of cur is new.
func delta(prev, cur float64) float64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// Refusal reasons: the closed set of allocations_refused{reason} (§10).
const (
	RefusedQuotaUser  = "quota_user"
	RefusedQuotaTotal = "quota_total"
	RefusedCapacity   = "capacity"
)

// LogCounter counts allocation refusals in coturn's log, which coturn
// 4.18.0 does not expose as Prometheus counters. It reads coturn's
// standard output through a pipe, matches each line against fixed
// strings, adds to a counter and drops the line: no line is stored,
// written or forwarded (§10: coturn's log is discarded on the instance).
type LogCounter struct {
	// TotalQuota and Allocations tell a total-quota refusal from a
	// per-credential one: coturn answers both "486 Allocation Quota
	// Reached" (userdb.c check_new_allocation_quota).
	TotalQuota  int
	Allocations func() float64

	mu      sync.Mutex
	refused map[string]float64
}

// The log texts of coturn 4.18.0 (ns_turn_server.c log_method and
// ns_turn_msg.c get_default_reason).
const (
	logAllocateError = "incoming packet ALLOCATE processed, error "
	logQuota         = "486: Allocation Quota Reached"
	logBandwidth     = "486: Allocation Bandwidth Quota Reached"
	logCapacity      = "508:"
)

// Line counts one log line.
func (c *LogCounter) Line(line string) {
	i := strings.Index(line, logAllocateError)
	if i < 0 {
		return
	}
	rest := line[i+len(logAllocateError):]
	var reason string
	switch {
	case strings.HasPrefix(rest, logBandwidth):
		reason = RefusedCapacity
	case strings.HasPrefix(rest, logQuota):
		reason = RefusedQuotaUser
		if c.TotalQuota > 0 && c.Allocations != nil && c.Allocations() >= float64(c.TotalQuota) {
			reason = RefusedQuotaTotal
		}
	case strings.HasPrefix(rest, logCapacity):
		reason = RefusedCapacity // no relay port left
	default:
		return
	}
	c.mu.Lock()
	if c.refused == nil {
		c.refused = map[string]float64{}
	}
	c.refused[reason]++
	c.mu.Unlock()
}

// Consume counts every line of r until it ends; the lines are dropped.
func (c *LogCounter) Consume(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 16<<10), 64<<10)
	for sc.Scan() {
		c.Line(sc.Text())
	}
	// A line over 64 KiB stops the scanner; drain the rest unread so
	// coturn never blocks on a full pipe.
	_, _ = io.Copy(io.Discard, r)
}

// Take returns the refusals counted since the last call and resets them.
func (c *LogCounter) Take() map[string]float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.refused
	c.refused = nil
	return out
}

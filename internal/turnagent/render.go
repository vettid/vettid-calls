// Package turnagent is turn-agent's logic (CALLING-SERVICE §4.4, §10):
// it renders coturn's configuration with the shared secret, runs coturn,
// counts what coturn reports, and emits the counters as metrics. It keeps
// nothing that names an address, a username or a session.
package turnagent

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"text/template"

	"github.com/vettid/vettid-calls/internal/issuer"
)

//go:embed turnserver.conf.tmpl
var confTemplate string

var tmpl = template.Must(template.New("turnserver.conf").Option("missingkey=error").Parse(confTemplate))

// Default caps (§7.2; D15, D16).
const (
	DefaultMaxKbps      = 256  // per allocation, each direction, while calls are voice only (D15)
	DefaultCapacityKbps = 4000 // in total, staging (D16)
	DefaultUserQuota    = 10   // allocations per credential
	DefaultTotalQuota   = 100  // allocations in total, staging (D16)
	DefaultPromPort     = 9641 // coturn's Prometheus port, on 127.0.0.1
)

// deniedPeers are the ranges of §7.2 that a relay may not send to, as
// CIDR blocks (converted to coturn's first-last form when rendered).
var deniedPeers = []string{
	// IPv4
	"0.0.0.0/8",       // "this network"
	"10.0.0.0/8",      // private (RFC 1918)
	"100.64.0.0/10",   // shared address space (RFC 6598)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local; holds the instance metadata (169.254.169.254) and DNS (169.254.169.253)
	"172.16.0.0/12",   // private (RFC 1918)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation (TEST-NET-1)
	"192.88.99.0/24",  // former 6to4 relay anycast
	"192.168.0.0/16",  // private (RFC 1918)
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation (TEST-NET-2)
	"203.0.113.0/24",  // documentation (TEST-NET-3)
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, and the limited broadcast address
	// IPv6
	"::/127",         // unspecified and loopback
	"::ffff:0:0/96",  // IPv4-mapped
	"64:ff9b::/96",   // NAT64, well-known prefix (reaches IPv4 through a translator)
	"64:ff9b:1::/48", // NAT64, local use
	"100::/64",       // discard-only
	"2001:db8::/32",  // documentation
	"3fff::/20",      // documentation (RFC 9637)
	"fc00::/7",       // unique-local; holds the instance metadata (fd00:ec2::254) and DNS (fd00:ec2::253)
	"fe80::/10",      // link-local
	"ff00::/8",       // multicast
}

// Params are what the configuration is rendered from.
type Params struct {
	// Realm is the server's name (turn.staging.vettid.org).
	Realm string
	// Secrets are the shared secrets, the current one first (§8.3).
	Secrets []string
	// PrivateIPv4 is the instance's private IPv4 address and PublicIPv4
	// the Elastic IP it is reached at (coturn's external-ip mapping).
	PrivateIPv4, PublicIPv4 netip.Addr
	// IPv6 is the instance's fixed IPv6 address (optional, §7.4).
	IPv6 netip.Addr
	// OwnNetworks are the service's own network ranges (the VPC's IPv4
	// and IPv6 blocks), denied as peers apart from the addresses above.
	OwnNetworks []netip.Prefix
	// Caps; zero means the default.
	MaxKbps, CapacityKbps, UserQuota, TotalQuota int
	PrometheusPort                               int
	// RunDir holds the rendered configuration and the pid file (a tmpfs).
	RunDir string
}

// view is what the template sees.
type view struct {
	Realm, ExternalIPv4, RunDir                   string
	Secrets, ListenIPs, DeniedPeers, AllowedPeers []string
	MaxKbps, MaxBps, CapacityKbps, CapacityBps    int
	CapacityAllocations, UserQuota, TotalQuota    int
	PrometheusPort                                int
}

func orDefault(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}

// Range renders a CIDR block in coturn's "first-last" form.
func Range(p netip.Prefix) string {
	p = p.Masked()
	first := p.Addr()
	b := first.AsSlice()
	bits := p.Bits()
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 0x80 >> j
			}
		}
	}
	last, _ := netip.AddrFromSlice(b)
	return first.String() + "-" + last.String()
}

// secretOK: what the coturn configuration parser keeps intact on one
// line (base64 text of the secret; turncred.ParseSet checked it).
func secretOK(s string) bool {
	if s == "" || len(s) > 512 || s[0] == '"' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// Render returns coturn's configuration.
func Render(p Params) ([]byte, error) {
	if err := issuer.ValidHost(p.Realm); err != nil {
		return nil, fmt.Errorf("turnagent: realm: %w", err)
	}
	if len(p.Secrets) == 0 {
		return nil, errors.New("turnagent: no secret")
	}
	for _, s := range p.Secrets {
		if !secretOK(s) {
			return nil, errors.New("turnagent: a secret is not base64 text")
		}
	}
	if !p.PrivateIPv4.Is4() || !p.PublicIPv4.Is4() {
		return nil, errors.New("turnagent: the private and public IPv4 addresses are required")
	}
	if p.IPv6.IsValid() && (!p.IPv6.Is6() || p.IPv6.Is4In6()) {
		return nil, errors.New("turnagent: the IPv6 address is not IPv6")
	}
	if p.RunDir == "" || strings.ContainsAny(p.RunDir, " \t\n\"") {
		return nil, errors.New("turnagent: bad run directory")
	}
	v := view{Realm: p.Realm, Secrets: p.Secrets, RunDir: p.RunDir,
		MaxKbps: orDefault(p.MaxKbps, DefaultMaxKbps), CapacityKbps: orDefault(p.CapacityKbps, DefaultCapacityKbps),
		UserQuota: orDefault(p.UserQuota, DefaultUserQuota), TotalQuota: orDefault(p.TotalQuota, DefaultTotalQuota),
		PrometheusPort: orDefault(p.PrometheusPort, DefaultPromPort)}
	if v.MaxKbps < 8 || v.CapacityKbps < v.MaxKbps || v.UserQuota < 1 || v.TotalQuota < 1 {
		return nil, errors.New("turnagent: caps out of range")
	}
	v.MaxBps, v.CapacityBps = v.MaxKbps*1000/8, v.CapacityKbps*1000/8
	v.CapacityAllocations = v.CapacityBps / v.MaxBps
	v.ListenIPs = []string{p.PrivateIPv4.String()}
	v.ExternalIPv4 = p.PublicIPv4.String() + "/" + p.PrivateIPv4.String()
	v.AllowedPeers = []string{p.PublicIPv4.String()}
	if p.IPv6.IsValid() {
		v.ListenIPs = append(v.ListenIPs, p.IPv6.String())
		v.AllowedPeers = append(v.AllowedPeers, p.IPv6.String())
	}
	for _, c := range deniedPeers {
		v.DeniedPeers = append(v.DeniedPeers, Range(netip.MustParsePrefix(c)))
	}
	for _, n := range p.OwnNetworks {
		if !n.IsValid() {
			return nil, errors.New("turnagent: bad own network")
		}
		v.DeniedPeers = append(v.DeniedPeers, Range(n))
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("turnagent: rendering: %w", err)
	}
	return buf.Bytes(), nil
}

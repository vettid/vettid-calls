package turnagent

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

const (
	secA = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	secB = "//////////////////////////////////////////8="
)

func params() Params {
	return Params{
		Realm:       "turn.staging.vettid.org",
		Secrets:     []string{secB, secA},
		PrivateIPv4: netip.MustParseAddr("10.40.0.12"),
		PublicIPv4:  netip.MustParseAddr("198.51.100.20"),
		IPv6:        netip.MustParseAddr("2600:1f18:1234:5600::20"),
		OwnNetworks: []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16"), netip.MustParsePrefix("2600:1f18:1234:5600::/56")},
		RunDir:      "/run/vettid-calls",
	}
}

// options returns the rendered file as option → values (comments and
// blank lines dropped), parsed the way coturn parses a line.
func options(t *testing.T, conf []byte) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, line := range strings.Split(string(conf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		name, value, _ := strings.Cut(line, "=")
		out[name] = append(out[name], value)
	}
	return out
}

func one(t *testing.T, o map[string][]string, name, want string) {
	t.Helper()
	if v := o[name]; len(v) != 1 || v[0] != want {
		t.Errorf("%s = %q, want %q", name, v, want)
	}
}

// Every rule of §7.2, as coturn 4.18.0 spells it.
func TestRender(t *testing.T) {
	conf, err := Render(params())
	if err != nil {
		t.Fatal(err)
	}
	o := options(t, conf)
	// Credentials: TURN REST, every secret, the current one first.
	one(t, o, "use-auth-secret", "")
	one(t, o, "realm", "turn.staging.vettid.org")
	one(t, o, "server-name", "turn.staging.vettid.org")
	if s := o["static-auth-secret"]; len(s) != 2 || s[0] != secB || s[1] != secA {
		t.Errorf("secrets %q", s)
	}
	// Listeners and addresses.
	one(t, o, "listening-port", "3478")
	if l := strings.Join(o["listening-ip"], ","); l != "10.40.0.12,2600:1f18:1234:5600::20" {
		t.Errorf("listening-ip %s", l)
	}
	if l := strings.Join(o["relay-ip"], ","); l != "10.40.0.12,2600:1f18:1234:5600::20" {
		t.Errorf("relay-ip %s", l)
	}
	one(t, o, "external-ip", "198.51.100.20/10.40.0.12")
	one(t, o, "min-port", "49152")
	one(t, o, "max-port", "65535")
	one(t, o, "no-tls", "")
	// Relaying.
	one(t, o, "no-tcp-relay", "")
	one(t, o, "no-multicast-peers", "")
	// Caps: bytes per second (256 kbit/s, 120 Mbit/s), quotas.
	one(t, o, "max-bps", "32000")
	one(t, o, "bps-capacity", "15000000")
	one(t, o, "user-quota", "10")
	one(t, o, "total-quota", "100")
	// Counters on loopback, no username labels.
	one(t, o, "prometheus", "")
	one(t, o, "prometheus-address", "127.0.0.1")
	one(t, o, "prometheus-port", "9641")
	one(t, o, "log-file", "stdout")
	one(t, o, "verbose", "")
	one(t, o, "pidfile", "/run/vettid-calls/turnserver.pid")
	if !strings.Contains(string(conf), "admits 469 allocations; with total-quota 100, at most\n# 100 allocations") {
		t.Error("the capacity note")
	}

	// What §7.2 rules out must not be switched on, and no deprecated
	// negative form is written (coturn 4.18.0 logs those as errors).
	for _, opt := range []string{"cli", "cli-ip", "cli-port", "cli-password", "web-admin", "web-admin-ip", "dtls",
		"rfc5780", "stun-backward-compatibility", "rfc3489-compatibility", "software-attribute", "Verbose",
		"prometheus-username-labels", "lt-cred-mech", "user", "no-auth", "allow-loopback-peers",
		"no-cli", "no-rfc5780", "no-software-attribute", "no-udp-relay", "no-stun", "no-udp", "no-tcp",
		"tls-listening-port", "cert", "pkey", "syslog", "userdb", "redis-userdb", "psql-userdb",
		"mysql-userdb", "mongo-userdb", "check-origin-consistency", "mobility"} {
		if _, ok := o[opt]; ok {
			t.Errorf("%s is set", opt)
		}
	}
}

func inRanges(t *testing.T, ranges []string, ip string) bool {
	t.Helper()
	a := netip.MustParseAddr(ip)
	for _, r := range ranges {
		lo, hi, ok := strings.Cut(r, "-")
		if !ok {
			t.Fatalf("%q is not a range", r)
		}
		l, h := netip.MustParseAddr(lo), netip.MustParseAddr(hi)
		if l.Compare(a) <= 0 && a.Compare(h) <= 0 {
			return true
		}
	}
	return false
}

// §7.2: where a relay may send.
func TestDeniedPeers(t *testing.T) {
	conf, err := Render(params())
	if err != nil {
		t.Fatal(err)
	}
	o := options(t, conf)
	denied, allowed := o["denied-peer-ip"], o["allowed-peer-ip"]
	rangeRE := regexp.MustCompile(`^[0-9a-f.:]+-[0-9a-f.:]+$`)
	for _, r := range denied {
		if !rangeRE.MatchString(r) {
			t.Errorf("%q: coturn takes IP-IP ranges, not CIDR", r)
		}
	}
	for _, ip := range []string{
		"0.0.0.0", "10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254", "169.254.169.253",
		"172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.7",
		"203.0.113.9", "224.0.0.251", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "64:ff9b::a00:1", "64:ff9b:1::1", "100::1",
		"2001:db8::1", "3fff::1", "fd00:ec2::254", "fd00:ec2::253", "fc00::1", "fe80::1", "ff02::1",
		"2600:1f18:1234:5600::99", // the service's own IPv6 network
	} {
		if !inRanges(t, denied, ip) {
			t.Errorf("%s is not denied", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1", "2a00:1450::1", "2001:4860::8888"} {
		if inRanges(t, denied, ip) {
			t.Errorf("%s is denied", ip)
		}
	}
	// The server's own public addresses stay allowed (an allowed rule
	// wins in coturn), so both-sides-relayed calls are not ruled out.
	if strings.Join(allowed, ",") != "198.51.100.20,2600:1f18:1234:5600::20" {
		t.Errorf("allowed %q", allowed)
	}
}

func TestRange(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8":    "10.0.0.0-10.255.255.255",
		"10.1.2.3/8":    "10.0.0.0-10.255.255.255",
		"100.64.0.0/10": "100.64.0.0-100.127.255.255",
		"::/127":        "::-::1",
		"fc00::/7":      "fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"::ffff:0:0/96": "::ffff:0.0.0.0-::ffff:255.255.255.255",
		"8.8.8.8/32":    "8.8.8.8-8.8.8.8",
	} {
		if got := Range(netip.MustParsePrefix(in)); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestRenderCaps(t *testing.T) {
	p := params()
	p.MaxKbps, p.CapacityKbps, p.TotalQuota, p.UserQuota = 3000, 24000, 200, 5 // C4's video cap
	conf, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	o := options(t, conf)
	one(t, o, "max-bps", "375000")
	one(t, o, "bps-capacity", "3000000")
	one(t, o, "total-quota", "200")
	one(t, o, "user-quota", "5")
	if !strings.Contains(string(conf), "admits 8 allocations; with total-quota 200, at most\n# 8 allocations") {
		t.Error("the capacity note")
	}
}

// The defaults are sized for C4 (D15: 3 Mbit/s an allocation with video):
// 40 allocations, five calls at 8 allocations each. Voice is bounded by
// total-quota instead.
func TestDefaultCapacity(t *testing.T) {
	const c4Kbps, perCall, calls = 3000, 8, 5
	if got := CapacityAllocations(c4Kbps*1000/8, DefaultCapacityKbps*1000/8); got != perCall*calls {
		t.Errorf("C4: %d allocations, want %d", got, perCall*calls)
	}
	if got := CapacityAllocations(DefaultMaxKbps*1000/8, DefaultCapacityKbps*1000/8); got < DefaultTotalQuota {
		t.Errorf("voice: %d allocations, below total-quota %d", got, DefaultTotalQuota)
	}
	p := params()
	p.MaxKbps = c4Kbps
	conf, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "admits 40 allocations; with total-quota 100, at most\n# 40 allocations") {
		t.Error("the capacity note at C4's cap")
	}
}

// coturn 4.18.0 gives the last allocation what is left of bps-capacity.
func TestCapacityAllocations(t *testing.T) {
	for _, c := range []struct{ maxBps, capBps, want int }{
		{32000, 500000, 16}, // 15 at the full rate and one at 20000
		{32000, 480000, 15},
		{375000, 15000000, 40},
		{375000, 375000, 1},
		{375000, 375001, 2},
	} {
		if got := CapacityAllocations(c.maxBps, c.capBps); got != c.want {
			t.Errorf("%d/%d: %d, want %d", c.capBps, c.maxBps, got, c.want)
		}
	}
}

func TestRenderRefuses(t *testing.T) {
	cases := map[string]func(*Params){
		"no secret":         func(p *Params) { p.Secrets = nil },
		"secret with space": func(p *Params) { p.Secrets = []string{"a b"} },
		"secret with quote": func(p *Params) { p.Secrets = []string{`"abc`} },
		"secret newline":    func(p *Params) { p.Secrets = []string{"abc\nno-tcp-relay=false"} },
		"no realm":          func(p *Params) { p.Realm = "" },
		"realm injection":   func(p *Params) { p.Realm = "x\ncli" },
		"no public v4":      func(p *Params) { p.PublicIPv4 = netip.Addr{} },
		"v6 as private v4":  func(p *Params) { p.PrivateIPv4 = netip.MustParseAddr("::1") },
		"v4 as v6":          func(p *Params) { p.IPv6 = netip.MustParseAddr("::ffff:1.2.3.4") },
		"capacity < cap":    func(p *Params) { p.CapacityKbps = 100 },
		"capacity > 32 bit": func(p *Params) { p.CapacityKbps = 10_000_001 },
		"run dir":           func(p *Params) { p.RunDir = "" },
	}
	for name, mut := range cases {
		p := params()
		mut(&p)
		if _, err := Render(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// IPv6 is optional.
	p := params()
	p.IPv6 = netip.Addr{}
	conf, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if o := options(t, conf); len(o["listening-ip"]) != 1 || len(o["allowed-peer-ip"]) != 1 {
		t.Fatal("IPv4 only")
	}
}

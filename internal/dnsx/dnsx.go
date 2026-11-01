// Package dnsx wraps miekg/dns with the small set of behaviours subsoil needs:
// resolver rotation, pacing, canonical RRsets and zone transfers.
package dnsx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Resolver performs queries through one or more recursive resolvers.
type Resolver struct {
	servers []string
	timeout time.Duration
	limiter *Limiter
	queries atomic.Int64

	mu   sync.Mutex
	next int
	vlog func(format string, args ...any)
}

// New builds a resolver. qps <= 0 disables pacing.
func New(servers []string, timeout time.Duration, qps int) (*Resolver, error) {
	if len(servers) == 0 {
		return nil, errors.New("no resolvers configured")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{
		servers: servers,
		timeout: timeout,
		limiter: NewLimiter(qps),
	}, nil
}

// Servers returns the configured resolver endpoints.
func (r *Resolver) Servers() []string { return append([]string(nil), r.servers...) }

// Queries returns the number of exchanges attempted.
func (r *Resolver) Queries() int64 { return r.queries.Load() }

// ParseServers accepts a comma-separated list of "system", bare IPs,
// hostnames, or host:port endpoints. It returns de-duplicated host:port
// addresses in the order given.
func ParseServers(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("no resolvers configured")
	}

	var out []string
	seen := make(map[string]struct{})
	add := func(addr string) {
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}

	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.EqualFold(token, "system") {
			sys := systemResolvers()
			if len(sys) == 0 {
				return nil, errors.New("no system resolvers found in /etc/resolv.conf")
			}
			for _, addr := range sys {
				add(addr)
			}
			continue
		}
		addr, err := normalizeServer(token)
		if err != nil {
			return nil, err
		}
		add(addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid resolver list %q", spec)
	}
	return out, nil
}

func normalizeServer(token string) (string, error) {
	host, port, err := net.SplitHostPort(token)
	if err != nil {
		host, port = token, "53"
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		} else if strings.Contains(host, ":") && net.ParseIP(host) == nil {
			return "", fmt.Errorf("invalid resolver %q", token)
		}
	}
	host = strings.TrimSuffix(host, ".")
	if port == "" {
		port = "53"
	}
	if !validResolverHost(host) {
		return "", fmt.Errorf("invalid resolver host %q", host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid resolver port %q", port)
	}
	return net.JoinHostPort(host, port), nil
}

func validResolverHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func systemResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			addr := fields[1]
			if net.ParseIP(addr) == nil {
				continue
			}
			out = append(out, net.JoinHostPort(addr, "53"))
		}
	}
	return out
}

func (r *Resolver) pick() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.servers[r.next%len(r.servers)]
	r.next++
	return s
}

// SetVerboseLog installs a hook for per-query diagnostics.
func (r *Resolver) SetVerboseLog(fn func(format string, args ...any)) { r.vlog = fn }

func (r *Resolver) vlogf(format string, args ...any) {
	if r.vlog != nil {
		r.vlog(format, args...)
	}
}

// Exchange sends m, falls back across servers on transport errors, REFUSED and
// SERVFAIL, and retries over TCP when the UDP answer is truncated.
func (r *Resolver) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if err := r.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	r.queries.Add(1)

	q := describeQuestion(m)
	var lastErr error
	for range r.servers {
		server := r.pick()
		start := time.Now()

		resp, err := r.exchange(ctx, m, server, "udp")
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", server, err)
			r.vlogf("dns %s @%s error: %v", q, server, err)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if resp.Truncated {
			r.vlogf("dns %s @%s truncated, retrying over TCP", q, server)
			resp, err = r.exchange(ctx, m, server, "tcp")
			if err != nil {
				lastErr = fmt.Errorf("%s (tcp): %w", server, err)
				r.vlogf("dns %s @%s tcp error: %v", q, server, err)
				continue
			}
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("%s: %s", server, RCodeString(resp.Rcode))
			r.vlogf("dns %s @%s -> %s, trying next resolver", q, server, RCodeString(resp.Rcode))
			continue
		}

		r.vlogf("dns %s @%s -> %s, %d answer(s), %s", q, server, RCodeString(resp.Rcode),
			len(resp.Answer), time.Since(start).Round(time.Millisecond))
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("dnsx: exchange failed")
	}
	r.vlogf("dns %s failed: %v", q, lastErr)
	return nil, lastErr
}

func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, server, network string) (*dns.Msg, error) {
	qctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	c := &dns.Client{Net: network, Timeout: r.timeout}
	resp, _, err := c.ExchangeContext(qctx, m, server)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty response")
	}
	return resp, nil
}

func describeQuestion(m *dns.Msg) string {
	if m == nil || len(m.Question) == 0 {
		return "<?>"
	}
	q := m.Question[0]
	typ := dns.TypeToString[q.Qtype]
	if typ == "" {
		typ = fmt.Sprintf("TYPE%d", q.Qtype)
	}
	return typ + " " + strings.TrimSuffix(q.Name, ".")
}

// Lookup queries name/type and returns the answer RRs plus the response code.
func (r *Resolver) Lookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, int, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	// EDNS0 without client-subnet: keeps our source network out of the query.
	m.SetEdns0(1232, false)

	resp, err := r.Exchange(ctx, m)
	if err != nil {
		return nil, 0, err
	}
	return resp.Answer, resp.Rcode, nil
}

// LookupType is Lookup with the type given as a string ("A", "MX", ...).
func (r *Resolver) LookupType(ctx context.Context, name, typ string) ([]dns.RR, int, error) {
	t, ok := dns.StringToType[strings.ToUpper(typ)]
	if !ok {
		return nil, 0, fmt.Errorf("dnsx: unknown record type %q", typ)
	}
	return r.Lookup(ctx, name, t)
}

// ResolveIPs returns the A/AAAA addresses for name.
func (r *Resolver) ResolveIPs(ctx context.Context, name string) ([]string, error) {
	set := make(map[string]struct{})
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		rrs, _, err := r.Lookup(ctx, name, t)
		if err != nil {
			return nil, err
		}
		for _, rr := range rrs {
			switch v := rr.(type) {
			case *dns.A:
				set[v.A.String()] = struct{}{}
			case *dns.AAAA:
				set[v.AAAA.String()] = struct{}{}
			}
		}
	}
	return sortedKeys(set), nil
}

// ResolveHosts resolves a nameserver hostname to dialable addresses.
func (r *Resolver) ResolveHosts(ctx context.Context, name string) ([]string, error) {
	if ip := net.ParseIP(strings.TrimSuffix(name, ".")); ip != nil {
		return []string{ip.String()}, nil
	}
	ips, err := r.ResolveIPs(ctx, name)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// AXFR attempts a zone transfer from the given nameserver address.
func (r *Resolver) AXFR(ctx context.Context, zone, address string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))

	t := &dns.Transfer{
		DialTimeout: r.timeout,
		ReadTimeout: r.timeout,
	}
	ch, err := t.In(m, address)
	if err != nil {
		return nil, err
	}
	var out []dns.RR
	for {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case env, ok := <-ch:
			if !ok {
				return out, nil
			}
			if env.Error != nil {
				return out, env.Error
			}
			out = append(out, env.RR...)
		}
	}
}

// CanonicalRR renders rr deterministically: TTL zeroed, owner lowercased,
// class omitted. Sorting a set of these gives a stable RRset fingerprint.
func CanonicalRR(rr dns.RR) string {
	c := dns.Copy(rr)
	c.Header().Ttl = 0
	c.Header().Name = strings.ToLower(c.Header().Name)
	c.Header().Class = dns.ClassINET
	return c.String()
}

// CanonicalSet normalises, sorts and de-duplicates an RRset.
func CanonicalSet(rrs []dns.RR) []string {
	set := make(map[string]struct{}, len(rrs))
	for _, rr := range rrs {
		set[CanonicalRR(rr)] = struct{}{}
	}
	return sortedKeys(set)
}

// RRsByType returns the canonical strings for RRs of the given type.
func RRsByType(rrs []dns.RR, t uint16) []string {
	var out []string
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			out = append(out, CanonicalRR(rr))
		}
	}
	sort.Strings(out)
	return out
}

// IPs extracts A and AAAA addresses from an RRset.
func IPs(rrs []dns.RR) []string {
	set := make(map[string]struct{})
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			set[v.A.String()] = struct{}{}
		case *dns.AAAA:
			set[v.AAAA.String()] = struct{}{}
		}
	}
	return sortedKeys(set)
}

// CNAMEs extracts CNAME targets (without trailing dot).
func CNAMEs(rrs []dns.RR) []string {
	set := make(map[string]struct{})
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok {
			set[strings.ToLower(strings.TrimSuffix(c.Target, "."))] = struct{}{}
		}
	}
	return sortedKeys(set)
}

// TXTValues joins the character-strings of each TXT record.
func TXTValues(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	sort.Strings(out)
	return out
}

// Names extracts names from NS/MX/PTR records without the trailing dot.
func Names(rrs []dns.RR) []string {
	set := make(map[string]struct{})
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.NS:
			set[strings.ToLower(strings.TrimSuffix(v.Ns, "."))] = struct{}{}
		case *dns.MX:
			set[strings.ToLower(strings.TrimSuffix(v.Mx, "."))] = struct{}{}
		case *dns.PTR:
			set[strings.ToLower(strings.TrimSuffix(v.Ptr, "."))] = struct{}{}
		}
	}
	return sortedKeys(set)
}

// RCodeString renders a DNS rcode for reports.
func RCodeString(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}

// HashSet returns the sorted, de-duplicated RRset used for evidence data.
func HashSet(rrs []dns.RR) []string { return CanonicalSet(rrs) }

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Limiter paces queries to an average rate with jitter.
type Limiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

// NewLimiter returns nil when qps <= 0 (unlimited).
func NewLimiter(qps int) *Limiter {
	if qps <= 0 {
		return nil
	}
	return &Limiter{interval: time.Second / time.Duration(qps)}
}

// Wait blocks until the next query slot. Jitter of ±25% avoids a perfectly
// regular packet cadence.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	iv := time.Duration(float64(l.interval) * (0.75 + rand.Float64()*0.5))
	l.next = l.next.Add(iv)
	d := l.next.Sub(now)
	l.mu.Unlock()

	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Package testutil provides an in-process authoritative DNS server used by
// integration tests. It is not part of the subsoil binary.
package testutil

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Zone is a tiny in-memory authoritative zone.
type Zone struct {
	Name      string
	Records   map[string]map[uint16][]dns.RR
	Wildcard  []dns.RR
	AllowAXFR bool
	Refuse    bool
	mu        sync.Mutex
}

// NewZone creates a zone for the given origin.
func NewZone(origin string) *Zone {
	return &Zone{
		Name:    dns.Fqdn(strings.ToLower(origin)),
		Records: make(map[string]map[uint16][]dns.RR),
	}
}

// Add parses and stores one or more presentation-format records.
func (z *Zone) Add(rrs ...string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(fmt.Sprintf("testutil: bad RR %q: %v", s, err))
		}
		name := strings.ToLower(rr.Header().Name)
		if z.Records[name] == nil {
			z.Records[name] = make(map[uint16][]dns.RR)
		}
		t := rr.Header().Rrtype
		z.Records[name][t] = append(z.Records[name][t], rr)
	}
}

// SetWildcard sets the records answered for any unknown name in the zone.
func (z *Zone) SetWildcard(rrs ...string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.Wildcard = nil
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		z.Wildcard = append(z.Wildcard, rr)
	}
}

// FullName returns the origin without the trailing dot.
func (z *Zone) FullName() string { return strings.TrimSuffix(z.Name, ".") }

// Start launches UDP and TCP listeners on the same loopback port.
func (z *Zone) Start(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = ln.Close()
		t.Fatalf("listen udp: %v", err)
	}

	h := dns.HandlerFunc(z.serve)
	udp := &dns.Server{PacketConn: pc, Handler: h}
	tcp := &dns.Server{Listener: ln, Handler: h}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	})
	time.Sleep(50 * time.Millisecond)
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func (z *Zone) serve(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if z.Refuse {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)

	if q.Qtype == dns.TypeAXFR {
		z.serveAXFR(w, r)
		return
	}

	z.mu.Lock()
	answers := z.lookupLocked(name, q.Qtype)
	z.mu.Unlock()

	if len(answers) > 0 {
		m.Answer = answers
		_ = w.WriteMsg(m)
		return
	}
	if name != z.Name {
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

func (z *Zone) lookupLocked(name string, qtype uint16) []dns.RR {
	if set, ok := z.Records[name]; ok {
		if rrs := set[qtype]; len(rrs) > 0 {
			return rrs
		}
		if cn := set[dns.TypeCNAME]; len(cn) > 0 && qtype != dns.TypeCNAME {
			out := append([]dns.RR(nil), cn...)
			if target, ok := cn[0].(*dns.CNAME); ok {
				out = append(out, z.lookupLocked(strings.ToLower(target.Target), qtype)...)
			}
			return out
		}
	}

	origin := strings.TrimSuffix(z.Name, ".")
	if len(z.Wildcard) > 0 && strings.HasSuffix(strings.TrimSuffix(name, "."), "."+origin) {
		var out []dns.RR
		for _, rr := range z.Wildcard {
			if rr.Header().Rrtype != qtype && rr.Header().Rrtype != dns.TypeCNAME {
				continue
			}
			c := dns.Copy(rr)
			c.Header().Name = name
			out = append(out, c)
		}
		return out
	}
	return nil
}

func (z *Zone) serveAXFR(w dns.ResponseWriter, r *dns.Msg) {
	if !z.AllowAXFR {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	z.mu.Lock()
	var rrs []dns.RR
	var soa dns.RR
	for _, set := range z.Records {
		for _, list := range set {
			for _, rr := range list {
				if rr.Header().Rrtype == dns.TypeSOA && soa == nil {
					soa = rr
				}
			}
			rrs = append(rrs, list...)
		}
	}
	z.mu.Unlock()
	// A zone transfer must start and end with the SOA record.
	if soa != nil {
		rrs = append([]dns.RR{soa}, rrs...)
		rrs = append(rrs, soa)
	}

	ch := make(chan *dns.Envelope, 1)
	go func() {
		if len(rrs) > 0 {
			ch <- &dns.Envelope{RR: rrs}
		}
		close(ch)
	}()
	tr := new(dns.Transfer)
	_ = tr.Out(w, r, ch)
}

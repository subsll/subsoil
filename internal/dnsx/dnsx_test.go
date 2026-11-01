package dnsx

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"subsoil/internal/testutil"

	"github.com/miekg/dns"
)

func TestCanonicalSetStripsTTL(t *testing.T) {
	a := mustRR(t, "www.example.com. 300 IN A 192.0.2.1")
	b := mustRR(t, "www.example.com. 600 IN A 192.0.2.1")
	got := CanonicalSet([]dns.RR{a, b})
	if len(got) != 1 {
		t.Fatalf("expected 1 canonical RR, got %v", got)
	}
	if got[0] != "www.example.com.\t0\tIN\tA\t192.0.2.1" {
		t.Fatalf("unexpected canonical form %q", got[0])
	}
}

func TestParseName(t *testing.T) {
	good := map[string]string{
		"Example.COM.": "example.com",
		"a.b.example":  "a.b.example",
	}
	for in, want := range good {
		got, err := ParseName(in)
		if err != nil || got != want {
			t.Fatalf("ParseName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "exa mple.com", "-bad.example", "http://example.com"} {
		if _, err := ParseName(in); err == nil {
			t.Fatalf("ParseName(%q) should have failed", in)
		}
	}
}

func TestParseServers(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"1.1.1.1", []string{"1.1.1.1:53"}},
		{"1.1.1.1,8.8.8.8", []string{"1.1.1.1:53", "8.8.8.8:53"}},
		{"1.1.1.1:5353", []string{"1.1.1.1:5353"}},
		{"dns.google", []string{"dns.google:53"}},
		{"2606:4700:4700::1111", []string{"[2606:4700:4700::1111]:53"}},
		{"[2606:4700:4700::1111]:5353", []string{"[2606:4700:4700::1111]:5353"}},
		{"1.1.1.1,1.1.1.1", []string{"1.1.1.1:53"}},
	}
	for _, c := range cases {
		got, err := ParseServers(c.in)
		if err != nil {
			t.Fatalf("ParseServers(%q): %v", c.in, err)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("ParseServers(%q) = %v, want %v", c.in, got, c.want)
		}
	}

	if got := systemResolvers(); len(got) > 0 {
		mixed, err := ParseServers("system,9.9.9.9")
		if err != nil {
			t.Fatal(err)
		}
		if mixed[len(mixed)-1] != "9.9.9.9:53" {
			t.Fatalf("system list = %v", mixed)
		}
	}

	for _, bad := range []string{"", "bad host!", "1.1.1.1:0", "1.1.1.1:99999", "1.1.1.1:abc"} {
		if _, err := ParseServers(bad); err == nil {
			t.Fatalf("ParseServers(%q) should have failed", bad)
		}
	}
}

func TestVerboseQueryLog(t *testing.T) {
	z := testutil.NewZone("example.test")
	z.Add("example.test. 300 IN A 192.0.2.1")
	addr := z.Start(t)

	r, err := New([]string{addr}, 2*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	r.SetVerboseLog(func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	if _, _, err := r.Lookup(context.Background(), "example.test", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	logged := strings.Join(lines, "\n")
	if !strings.Contains(logged, "dns A example.test") || !strings.Contains(logged, "NOERROR") {
		t.Fatalf("verbose log = %q", logged)
	}
}

func TestFailoverOnRefused(t *testing.T) {
	bad := testutil.NewZone("example.test")
	bad.Refuse = true
	badAddr := bad.Start(t)

	good := testutil.NewZone("example.test")
	good.Add("example.test. 300 IN A 192.0.2.7")
	goodAddr := good.Start(t)

	r, err := New([]string{badAddr, goodAddr}, 2*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	rrs, rcode, err := r.Lookup(context.Background(), "example.test", dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("lookup after REFUSED: %v rcode=%d", err, rcode)
	}
	if ips := IPs(rrs); len(ips) != 1 || ips[0] != "192.0.2.7" {
		t.Fatalf("ips = %v", ips)
	}
}

func TestLookupAndAXFR(t *testing.T) {
	z := testutil.NewZone("example.test")
	z.Add(
		"example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 1 3600 600 86400 300",
		"example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN A 192.0.2.1",
		"example.test. 300 IN MX 10 mail.example.test.",
		"example.test. 300 IN TXT \"v=spf1 -all\"",
		"ns1.example.test. 300 IN A 127.0.0.1",
		"www.example.test. 300 IN A 192.0.2.10",
		"api.example.test. 300 IN CNAME www.example.test.",
	)
	z.AllowAXFR = true
	addr := z.Start(t)

	r, err := New([]string{addr}, 2*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	rrs, rcode, err := r.Lookup(ctx, "www.example.test", dns.TypeA)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("lookup: %v rcode=%d", err, rcode)
	}
	if ips := IPs(rrs); len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("ips = %v", ips)
	}

	rrs, _, err = r.Lookup(ctx, "example.test", dns.TypeTXT)
	if err != nil || len(TXTValues(rrs)) != 1 || TXTValues(rrs)[0] != "v=spf1 -all" {
		t.Fatalf("txt: %v %v", err, TXTValues(rrs))
	}

	rrs, _, err = r.Lookup(ctx, "api.example.test", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if cns := CNAMEs(rrs); len(cns) != 1 || cns[0] != "www.example.test" {
		t.Fatalf("cnames = %v", cns)
	}
	if ips := IPs(rrs); len(ips) != 1 || ips[0] != "192.0.2.10" {
		t.Fatalf("cname target ips = %v", ips)
	}

	records, err := r.AXFR(ctx, "example.test", addr)
	if err != nil {
		t.Fatalf("axfr: %v", err)
	}
	if len(records) < 8 {
		t.Fatalf("axfr returned %d records", len(records))
	}
}

func TestWildcardDetection(t *testing.T) {
	z := testutil.NewZone("wild.test")
	z.Add("wild.test. 300 IN A 192.0.2.1", "wild.test. 300 IN NS ns1.wild.test.")
	z.SetWildcard("*.wild.test. 300 IN A 192.0.2.99")
	addr := z.Start(t)

	r, err := New([]string{addr}, 2*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	w, err := DetectWildcard(context.Background(), r, "wild.test", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Enabled || len(w.IPs) != 1 || w.IPs[0] != "192.0.2.99" {
		t.Fatalf("wildcard = %+v", w)
	}
	if !WildcardMatch(w, []string{"192.0.2.99"}, nil) {
		t.Fatal("wildcard answer was not matched")
	}
	if WildcardMatch(w, []string{"192.0.2.50"}, nil) {
		t.Fatal("distinct address was matched as wildcard")
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

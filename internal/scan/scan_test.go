package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"subsoil/internal/evidence"
	"subsoil/internal/model"
	"subsoil/internal/report"
	"subsoil/internal/testutil"
)

func TestScanActive(t *testing.T) {
	z := testutil.NewZone("example.test")
	z.Add(
		"example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 1 3600 600 86400 300",
		"example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN A 192.0.2.1",
		"example.test. 300 IN MX 10 mail.example.test.",
		"example.test. 300 IN TXT \"v=spf1 -all\"",
		"_dmarc.example.test. 300 IN TXT \"v=DMARC1; p=none\"",
		"ns1.example.test. 300 IN A 127.0.0.1",
		"www.example.test. 300 IN A 192.0.2.10",
		"mail.example.test. 300 IN A 192.0.2.20",
		"api.example.test. 300 IN CNAME www.example.test.",
		"_sip._tcp.example.test. 300 IN SRV 10 5 5060 sip.example.test.",
		"10.2.0.192.in-addr.arpa. 300 IN PTR www.example.test.",
	)
	addr := z.Start(t)
	dir := t.TempDir()
	words := writeWords(t, dir, []string{"www", "mail", "api", "admin"})

	res, err := Run(context.Background(), Options{
		Domain:        "example.test",
		OutDir:        dir,
		Brute:         true,
		SRV:           true,
		PTR:           true,
		WordlistPaths: []string{words},
		Workers:       4,
		QPS:           0,
		Timeout:       2 * time.Second,
		Resolvers:     []string{addr},
		MaxHosts:      50,
	})
	if err != nil {
		t.Fatal(err)
	}

	hosts := map[string]model.Host{}
	for _, h := range res.Hosts {
		hosts[h.Name] = h
	}
	for _, want := range []string{"www.example.test", "mail.example.test", "api.example.test"} {
		h, ok := hosts[want]
		if !ok {
			t.Fatalf("missing host %s (got %v)", want, keys(hosts))
		}
		if !h.Resolved || h.Hash == "" {
			t.Fatalf("host %s not resolved or unhashed: %+v", want, h)
		}
	}
	if _, ok := hosts["admin.example.test"]; ok {
		t.Fatal("nonexistent admin.example.test was reported")
	}
	if got := hosts["www.example.test"].IPs; len(got) != 1 || got[0] != "192.0.2.10" {
		t.Fatalf("www ips = %v", got)
	}
	if got := hosts["api.example.test"].CNAME; got != "www.example.test" {
		t.Fatalf("api cname = %q", got)
	}

	if !res.Options.ResolveIPs {
		t.Fatal("ResolveIPs should default to true")
	}
	if res.Stats.BruteTried != 4 || res.Stats.BruteHits != 3 {
		t.Fatalf("brute stats = %+v", res.Stats)
	}

	var dmarc *model.RecordSet
	for i := range res.Records {
		if res.Records[i].Name == "_dmarc.example.test" && len(res.Records[i].RRs) == 1 {
			dmarc = &res.Records[i]
		}
	}
	if dmarc == nil || dmarc.SHA256 == "" {
		t.Fatalf("missing or unhashed DMARC record: %+v", res.Records)
	}

	if len(res.SRV) != 1 || res.SRV[0].Port != 5060 || res.SRV[0].Target != "sip.example.test" {
		t.Fatalf("srv = %+v", res.SRV)
	}
	if len(res.PTR) != 1 || res.PTR[0].IP != "192.0.2.10" || res.PTR[0].Names[0] != "www.example.test" {
		t.Fatalf("ptr = %+v", res.PTR)
	}

	rep, err := evidence.VerifyFile(res.Evidence.File)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("evidence did not verify: %v", rep.Errors)
	}
	if rep.RootSHA256 != res.Evidence.RootSHA256 {
		t.Fatalf("root mismatch: %s vs %s", rep.RootSHA256, res.Evidence.RootSHA256)
	}
	raw, err := os.ReadFile(res.Evidence.File)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range res.Hosts {
		if !strings.Contains(string(raw), h.Hash) {
			t.Fatalf("host hash %s for %s is not in the evidence log", h.Hash, h.Name)
		}
	}

	files, err := report.Write(res, dir, []string{"text", "json", "md", "html"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing report file %s: %v", f, err)
		}
	}
	md, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "example.test") || !strings.Contains(string(md), res.Evidence.RootSHA256) {
		t.Fatal("markdown report is missing key content")
	}
}

func TestScanAXFR(t *testing.T) {
	z := testutil.NewZone("example.test")
	z.Add(
		"example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 1 3600 600 86400 300",
		"example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN A 192.0.2.1",
		"ns1.example.test. 300 IN A 127.0.0.1",
		"www.example.test. 300 IN A 192.0.2.10",
		"mail.example.test. 300 IN A 192.0.2.20",
	)
	z.AllowAXFR = true
	addr := z.Start(t)

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	old := axfrPort
	axfrPort = port
	defer func() { axfrPort = old }()

	res, err := Run(context.Background(), Options{
		Domain:    "example.test",
		OutDir:    t.TempDir(),
		AXFR:      true,
		Workers:   2,
		Timeout:   2 * time.Second,
		Resolvers: []string{addr},
		MaxHosts:  20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.AXFR) != 1 {
		t.Fatalf("axfr results = %+v", res.AXFR)
	}
	got := res.AXFR[0]
	if !got.OK || len(got.Records) < 5 {
		t.Fatalf("zone transfer failed: %+v", got)
	}
	if got.RecordsSHA256 == "" || got.RecordsSHA256 == got.SHA256 {
		t.Fatalf("records hash not recorded separately: %+v", got)
	}
	rep, err := evidence.VerifyFile(res.Evidence.File)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("evidence did not verify: %v", rep.Errors)
	}
}

func TestScanNoIPLookup(t *testing.T) {
	z := testutil.NewZone("example.test")
	z.Add(
		"example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 1 3600 600 86400 300",
		"example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN A 192.0.2.1",
		"ns1.example.test. 300 IN A 127.0.0.1",
		"www.example.test. 300 IN A 192.0.2.10",
	)
	addr := z.Start(t)
	dir := t.TempDir()
	words := writeWords(t, dir, []string{"www", "nope"})

	var stages []string
	res, err := Run(context.Background(), Options{
		Domain:        "example.test",
		OutDir:        dir,
		Brute:         true,
		PTR:           true,
		NoIPLookup:    true,
		Stage:         func(s string) { stages = append(stages, s) },
		WordlistPaths: []string{words},
		Workers:       2,
		QPS:           0,
		Timeout:       2 * time.Second,
		Resolvers:     []string{addr},
		MaxHosts:      10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Options.ResolveIPs {
		t.Fatal("ResolveIPs should be false")
	}
	if res.Options.PTR {
		t.Fatal("PTR should be disabled when IP lookup is off")
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("hosts = %+v", res.Hosts)
	}
	h := res.Hosts[0]
	if h.Name != "www.example.test" || !h.Resolved || !h.IPsHidden {
		t.Fatalf("host = %+v", h)
	}
	if len(h.IPs) != 0 || len(h.AAAA) != 0 {
		t.Fatalf("IPs leaked: %v %v", h.IPs, h.AAAA)
	}
	if len(res.PTR) != 0 {
		t.Fatalf("PTR results = %+v", res.PTR)
	}
	for _, want := range []string{"baseline DNS", "wildcard detection", "brute force", "collecting findings"} {
		found := false
		for _, stage := range stages {
			if stage == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing stage %q in %v", want, stages)
		}
	}

	f, err := os.Open(res.Evidence.File)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec struct {
			Type   string         `json:"type"`
			Target string         `json:"target"`
			Data   map[string]any `json:"data"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Type != "host" || rec.Target != "www.example.test" {
			continue
		}
		found = true
		if rec.Data["ips_hidden"] != true {
			t.Fatalf("host evidence does not mark hidden IPs: %v", rec.Data)
		}
		if ips, ok := rec.Data["ips"].([]any); !ok || len(ips) != 0 {
			t.Fatalf("host evidence leaked IPs: %v", rec.Data["ips"])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("host evidence record not found")
	}
}

func TestScanWildcardFiltering(t *testing.T) {
	z := testutil.NewZone("wild.test")
	z.Add(
		"wild.test. 300 IN NS ns1.wild.test.",
		"wild.test. 300 IN A 192.0.2.1",
		"real.wild.test. 300 IN A 192.0.2.50",
	)
	z.SetWildcard("*.wild.test. 300 IN A 192.0.2.99")
	addr := z.Start(t)

	dir := t.TempDir()
	words := writeWords(t, dir, []string{"real", "admin", "other"})
	res, err := Run(context.Background(), Options{
		Domain:        "wild.test",
		OutDir:        dir,
		Brute:         true,
		WordlistPaths: []string{words},
		Workers:       3,
		Timeout:       2 * time.Second,
		Resolvers:     []string{addr},
		MaxHosts:      20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Wildcard.Enabled {
		t.Fatal("wildcard was not detected")
	}
	if res.Wildcard.Filtered != 2 {
		t.Fatalf("filtered = %d, want 2", res.Wildcard.Filtered)
	}
	names := map[string]bool{}
	for _, h := range res.Hosts {
		names[h.Name] = true
	}
	if !names["real.wild.test"] {
		t.Fatalf("real host missing: %v", names)
	}
	if names["admin.wild.test"] || names["other.wild.test"] {
		t.Fatalf("wildcard false positives were reported: %v", names)
	}
}

func writeWords(t *testing.T, dir string, labels []string) string {
	t.Helper()
	path := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(path, []byte(strings.Join(labels, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func keys(m map[string]model.Host) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

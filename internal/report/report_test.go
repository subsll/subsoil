package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/subsll/subsoil/internal/model"
)

func fixture(t *testing.T) (*model.Result, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	res := &model.Result{
		Tool:       model.ToolName,
		Version:    "test",
		Domain:     "example.com",
		Started:    now.Add(-2 * time.Second),
		Finished:   now,
		DurationMS: 2000,
		Resolvers:  []string{"1.1.1.1:53"},
		Options: model.ScanOptions{
			Brute: true, Words: 5000, Workers: 20, QPS: 50, ResolveIPs: true,
			Sources: []string{"crt.sh"}, TimeoutSecond: 5, MaxHosts: 5000,
		},
		Records: []model.RecordSet{{
			Name: "example.com", Type: "A", RCode: "NOERROR",
			RRs:    []string{"example.com.\t0\tIN\tA\t192.0.2.1"},
			SHA256: "rrshash",
		}},
		Hosts: []model.Host{{
			Name: "www.example.com", IPs: []string{"192.0.2.1"},
			Sources: []string{"crt.sh"}, Resolved: true,
			FirstSeen: now, Hash: "deadbeef",
		}},
		Wildcard: model.Wildcard{Enabled: true, IPs: []string{"192.0.2.99"}, Filtered: 3},
		Stats:    model.Stats{DNSQueries: 42, BruteTried: 5000, BruteHits: 1},
		Evidence: model.EvidenceInfo{
			File: filepath.Join(dir, "evidence.jsonl"), Records: 7,
			RootSHA256: "rootroot", FileSHA256: "filehash", ChainOK: true,
		},
	}
	return res, dir
}

func TestWriteAllFormats(t *testing.T) {
	res, dir := fixture(t)
	files, err := Write(res, dir, []string{"text", "json", "md", "html", "graph"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"evidence.jsonl.sha256", "graph.html", "hosts.csv", "report.html", "report.json", "report.md", "report.txt", "subdomains.txt"}
	for _, w := range want {
		if !contains(files, w) {
			t.Fatalf("missing %s in %v", w, files)
		}
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}

	// The manifest must match the bytes on disk.
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
	if len(lines) != len(files)-1 {
		t.Fatalf("manifest has %d lines for %d files", len(lines), len(files)-1)
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("bad manifest line %q", line)
		}
		data, err := os.ReadFile(filepath.Join(dir, fields[1]))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != fields[0] {
			t.Fatalf("checksum mismatch for %s", fields[1])
		}
	}

	// Text output must be colour-free on disk.
	txt, err := os.ReadFile(filepath.Join(dir, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(txt), "\x1b[") {
		t.Fatal("report.txt contains ANSI escapes")
	}
	if !strings.Contains(string(txt), "example.com") || !strings.Contains(string(txt), "www.example.com") {
		t.Fatal("report.txt is missing expected content")
	}

	var got model.Result
	data, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.com" || len(got.Hosts) != 1 || got.Hosts[0].Hash != "deadbeef" {
		t.Fatalf("json round-trip mismatch: %+v", got)
	}

	md, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "deadbeef") || !strings.Contains(string(md), "rootroot") {
		t.Fatal("markdown is missing hashes")
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "www.example.com") || !strings.Contains(string(html), "rootroot") {
		t.Fatal("html is missing content")
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	res, dir := fixture(t)
	if _, err := Write(res, dir, []string{"pdf"}); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

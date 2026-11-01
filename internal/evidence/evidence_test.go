package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecorderAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := rec.Add("host", "www.example.com", "dns", map[string]any{
		"ips": []string{"192.0.2.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := rec.Add("host", "mail.example.com", "dns", map[string]any{
		"ips": []string{"192.0.2.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := rec.Close()
	if err != nil {
		t.Fatal(err)
	}

	if info.Records != 2 {
		t.Fatalf("records = %d, want 2", info.Records)
	}
	if info.RootSHA256 != second.Hash {
		t.Fatalf("root = %s, want %s", info.RootSHA256, second.Hash)
	}
	if first.Seq != 1 || second.Seq != 2 {
		t.Fatalf("bad sequence numbers: %d, %d", first.Seq, second.Seq)
	}

	rep, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain did not verify: %v", rep.Errors)
	}
	if rep.Records != 2 || rep.RootSHA256 != info.RootSHA256 {
		t.Fatalf("verify report mismatch: %+v", rep)
	}
	if rep.FileSHA256 != info.FileSHA256 {
		t.Fatalf("file hash mismatch: %s vs %s", rep.FileSHA256, info.FileSHA256)
	}
}

func TestCanonicalJSONHandlesMarkup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Add("http", "example.com", "http", map[string]any{
		"title": `<b>AT&T</b> & "quotes"`,
		"note":  "unicode: café",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("chain with markup did not verify: %v", rep.Errors)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Add("host", "www.example.com", "dns", map[string]any{
		"ips": []string{"192.0.2.1"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Add("host", "mail.example.com", "dns", map[string]any{
		"ips": []string{"192.0.2.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "192.0.2.1", "192.0.2.9", 1)
	if tampered == string(data) {
		t.Fatal("fixture did not contain the expected value")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("tampered log verified as OK")
	}
	if len(rep.Errors) == 0 || !strings.Contains(rep.Errors[0], "hash mismatch") {
		t.Fatalf("unexpected errors: %v", rep.Errors)
	}
}

func TestVerifyDetectsReordering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"a.example.com", "b.example.com"} {
		if _, err := rec.Add("host", host, "dns", map[string]any{"ips": []string{"192.0.2.1"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	if err := os.WriteFile(path, []byte(lines[1]+"\n"+lines[0]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("reordered log verified as OK")
	}
}

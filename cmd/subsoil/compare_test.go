package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/subsll/subsoil/internal/evidence"
)

func TestCmdCompareExitCodes(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "case")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("already captured\n")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	rec, err := evidence.NewRecorder(filepath.Join(caseDir, "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Add("http", "www.example.test", "http", map[string]any{
		"body_sha256": digest,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	oldFile := filepath.Join(dir, "old.bin")
	if err := os.WriteFile(oldFile, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdCompare([]string{oldFile, "--case", caseDir}); code != 0 {
		t.Fatalf("captured file exit = %d, want 0", code)
	}
	if code := cmdCompare([]string{"--hash", digest, "--case", caseDir}); code != 0 {
		t.Fatalf("captured hash exit = %d, want 0", code)
	}
	if code := cmdCompare([]string{oldFile, "--case", caseDir, "--json"}); code != 0 {
		t.Fatalf("JSON captured exit = %d, want 0", code)
	}
	if code := cmdCompare([]string{oldFile, "--case", filepath.Join(caseDir, "evidence.jsonl")}); code != 0 {
		t.Fatalf("direct evidence path exit = %d, want 0", code)
	}

	sidecar := filepath.Join(caseDir, "evidence.jsonl.sha256")
	if err := os.WriteFile(sidecar, []byte("0000000000000000000000000000000000000000000000000000000000000000  evidence.jsonl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdCompare([]string{oldFile, "--case", caseDir}); code != 2 {
		t.Fatalf("sidecar mismatch exit = %d, want 2", code)
	}
	if err := os.Remove(sidecar); err != nil {
		t.Fatal(err)
	}

	newFile := filepath.Join(dir, "new.bin")
	if err := os.WriteFile(newFile, []byte("new evidence\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdCompare([]string{newFile, "--case", caseDir}); code != 1 {
		t.Fatalf("new file exit = %d, want 1", code)
	}
	if code := cmdCompare([]string{oldFile, "--case", filepath.Join(dir, "missing")}); code != 2 {
		t.Fatalf("missing case exit = %d, want 2", code)
	}
	if code := cmdCompare([]string{"--hash", "not-a-hash", "--case", caseDir}); code != 2 {
		t.Fatalf("bad hash exit = %d, want 2", code)
	}
}

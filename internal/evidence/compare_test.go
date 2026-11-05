package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.bin")
	content := []byte("captured evidence\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, size, err := FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %s", got)
	}
	if size != int64(len(content)) {
		t.Fatalf("size = %d, want %d", size, len(content))
	}
}

func TestFindHashMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	body := sha256.Sum256([]byte("body"))
	bodyHash := hex.EncodeToString(body[:])
	nested := sha256.Sum256([]byte("nested"))
	nestedHash := hex.EncodeToString(nested[:])

	httpRec, err := rec.Add("http", "www.example.test", "http", map[string]any{
		"body_sha256": bodyHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Add("host", "www.example.test", "subsoil", map[string]any{
		"nested": map[string]any{"sha256": nestedHash},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	matches, err := FindHashMatches(path, bodyHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Field != "data.body_sha256" || matches[0].Seq != httpRec.Seq {
		t.Fatalf("body matches = %+v", matches)
	}

	matches, err = FindHashMatches(path, nestedHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Field != "data.nested.sha256" {
		t.Fatalf("nested matches = %+v", matches)
	}

	matches, err = FindHashMatches(path, httpRec.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Field != "hash" {
		t.Fatalf("record matches = %+v", matches)
	}

	matches, err = FindHashMatches(path, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("unexpected matches = %+v", matches)
	}

	if _, err := FindHashMatches(path, "not-a-hash"); err == nil {
		t.Fatal("expected invalid digest error")
	}
}

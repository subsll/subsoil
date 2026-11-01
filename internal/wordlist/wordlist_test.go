package wordlist

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedLists(t *testing.T) {
	small, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(small) < 4000 {
		t.Fatalf("small list has only %d entries", len(small))
	}
	large, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(large) <= len(small) {
		t.Fatalf("extended list (%d) is not larger than small (%d)", len(large), len(small))
	}
	for _, w := range small {
		if !ValidLabel(w) {
			t.Fatalf("invalid label in embedded list: %q", w)
		}
	}
	foundWWW := false
	for _, w := range small {
		if w == "www" {
			foundWWW = true
			break
		}
	}
	if !foundWWW {
		t.Fatal("embedded list is missing the www label")
	}
}

func TestLoadFileNormalises(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/words.txt"
	content := "WWW\nmail\n# comment\n*\nbad_label\napi.example.com\nwww\n\n-ok-\n"
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	words, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www", "mail", "api"}
	if len(words) != len(want) {
		t.Fatalf("got %v, want %v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Fatalf("got %v, want %v", words, want)
		}
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func TestLoadPathsFilesAndDedup(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(a, []byte("WWW\nmail\n# comment\napi.example.com\nwww\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("api\nwww\nn1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadPaths([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www", "mail", "api", "n1"}
	if len(res.Words) != len(want) {
		t.Fatalf("words = %v, want %v", res.Words, want)
	}
	for i := range want {
		if res.Words[i] != want[i] {
			t.Fatalf("words = %v, want %v", res.Words, want)
		}
	}
	if len(res.Sources) != 2 {
		t.Fatalf("sources = %v", res.Sources)
	}
}

func TestLoadPathsDirectoryAndGzip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("www\nmail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gzPath := filepath.Join(dir, "b.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte("api\nwww\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden.txt"), []byte("hidden\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := LoadPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www", "mail", "api"}
	if len(res.Words) != len(want) {
		t.Fatalf("words = %v, want %v", res.Words, want)
	}
	for i := range want {
		if res.Words[i] != want[i] {
			t.Fatalf("words = %v, want %v", res.Words, want)
		}
	}
	if len(res.Sources) != 2 {
		t.Fatalf("sources = %v, want 2", res.Sources)
	}

	direct, err := LoadFile(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 2 || direct[0] != "api" || direct[1] != "www" {
		t.Fatalf("gzip LoadFile = %v", direct)
	}
}

func TestLoadPathsErrors(t *testing.T) {
	if _, err := LoadPaths([]string{filepath.Join(t.TempDir(), "missing.txt")}); err == nil {
		t.Fatal("missing file should fail")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPaths([]string{dir}); err == nil {
		t.Fatal("directory without wordlists should fail")
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("***\n_\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPaths([]string{empty}); err == nil {
		t.Fatal("file without valid labels should fail")
	}
}

func TestLoadPathsStdin(t *testing.T) {
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("stdin1\nstdin2\n"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	os.Stdin = r
	defer func() { os.Stdin = old }()
	defer r.Close()

	res, err := LoadPaths([]string{"-"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Words) != 2 || res.Words[0] != "stdin1" || res.Words[1] != "stdin2" {
		t.Fatalf("stdin words = %v", res.Words)
	}
}

package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server")
		_, _ = w.Write([]byte("<html><head><title>Hello &amp; World</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	bodyDir := t.TempDir()
	res := Probe(context.Background(), host, Options{
		Timeout: 3 * time.Second, Insecure: true, Capture: true, BodyDir: bodyDir,
	})
	if res.Error != "" {
		t.Fatalf("probe error: %s", res.Error)
	}
	if res.Scheme != "https" || res.Status != 200 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Title != "Hello & World" {
		t.Fatalf("title = %q", res.Title)
	}
	if res.BodySHA256 == "" || res.BodyLen == 0 {
		t.Fatalf("missing body proof: %+v", res)
	}
	if res.TLS == nil || res.TLS.Subject == "" {
		t.Fatalf("missing TLS info: %+v", res.TLS)
	}
	if res.BodyFile == "" {
		t.Fatal("capture requested but no body file recorded")
	}
	if _, err := os.Stat(filepath.Join(bodyDir, filepath.Base(res.BodyFile))); err != nil {
		t.Fatalf("captured body missing: %v", err)
	}
}

func TestProbeHTTPFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>plain http</title></html>"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	res := Probe(context.Background(), host, Options{Timeout: 2 * time.Second, Insecure: true})
	if res.Error != "" {
		t.Fatalf("probe error: %s", res.Error)
	}
	if res.Scheme != "http" || res.Status != 200 || res.Title != "plain http" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		"<title> Simple </title>":                         "Simple",
		"<html><TITLE>UPPER</TITLE></html>":               "UPPER",
		"<title>multi\n line</title>":                     "multi line",
		"<title>a &lt; b</title>":                         "a < b",
		"no title here":                                   "",
		"<title>one</title><title>two</title>":            "one",
		"<title>" + strings.Repeat("x", 300) + "</title>": strings.Repeat("x", 200) + "…",
	}
	for in, want := range cases {
		if got := extractTitle([]byte(in)); got != want {
			t.Errorf("extractTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

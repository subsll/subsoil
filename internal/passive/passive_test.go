package passive

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"www.example.com", "www.example.com", true},
		{"*.dev.example.com", "dev.example.com", true},
		{"WWW.Example.COM.", "www.example.com", true},
		{"example.com", "", false},
		{"notexample.com", "", false},
		{"evil-example.com", "", false},
		{"a_b.example.com", "", false},
		{"-bad.example.com", "", false},
		{"www.example.com.evil.net", "", false},
	}
	for _, c := range cases {
		got, ok := Normalize(c.in, "example.com")
		if ok != c.ok || got != c.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCertSpotterSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") != "example.com" {
			t.Errorf("unexpected domain query %q", r.URL.Query().Get("domain"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"dns_names":["www.example.com","*.dev.example.com"]},
			{"dns_names":["mail.example.com","www.example.com"]},
			{"dns_names":["example.com","notexample.com"]}
		]`))
	}))
	defer srv.Close()

	s, ok := NewSource("certspotter", Options{
		Client:    srv.Client(),
		Timeout:   5 * time.Second,
		Endpoints: map[string]string{"certspotter": srv.URL},
	})
	if !ok {
		t.Fatal("certspotter source not available")
	}
	names, err := s.Lookup(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dev.example.com", "mail.example.com", "www.example.com"}
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("got %v, want %v", names, want)
		}
	}
}

func TestCrtShSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name_value":"a.example.com\nb.example.com","common_name":"a.example.com"}]`))
	}))
	defer srv.Close()

	s, ok := NewSource("crt.sh", Options{
		Client:    srv.Client(),
		Timeout:   5 * time.Second,
		Endpoints: map[string]string{"crt.sh": srv.URL},
	})
	if !ok {
		t.Fatal("crt.sh source not available")
	}
	names, err := s.Lookup(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "a.example.com" || names[1] != "b.example.com" {
		t.Fatalf("names = %v", names)
	}
}

func TestDefaultSourcesExcludeOTX(t *testing.T) {
	for _, s := range DefaultSources {
		if s == "otx" {
			t.Fatal("OTX should be opt-in because it requires an API key")
		}
	}
}

func TestOTXRequiresKey(t *testing.T) {
	s, ok := NewSource("otx", Options{Timeout: 2 * time.Second})
	if !ok {
		t.Fatal("otx source not available")
	}
	_, err := s.Lookup(t.Context(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "SUBSOIL_OTX_KEY") {
		t.Fatalf("error = %v, want a SUBSOIL_OTX_KEY hint", err)
	}
}

func TestOTXKeyHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-OTX-API-KEY"); got != "sekret" {
			t.Errorf("X-OTX-API-KEY = %q", got)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "subsoil/") {
			t.Errorf("User-Agent = %q, want a subsoil/ UA", got)
		}
		_, _ = w.Write([]byte(`{"passive_dns":[{"hostname":"www.example.com"},{"hostname":"*.dev.example.com"}]}`))
	}))
	defer srv.Close()

	s, ok := NewSource("otx", Options{
		Client:    srv.Client(),
		Timeout:   5 * time.Second,
		Endpoints: map[string]string{"otx": srv.URL},
		OTXKey:    "sekret",
	})
	if !ok {
		t.Fatal("otx source not available")
	}
	names, err := s.Lookup(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dev.example.com", "www.example.com"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", names, want)
	}
}

func TestOTXErrorDetail(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"Anonymous access to this endpoint is limited. Please authenticate."}`))
	}))
	defer srv.Close()

	s, ok := NewSource("otx", Options{
		Client:    srv.Client(),
		Timeout:   5 * time.Second,
		Endpoints: map[string]string{"otx": srv.URL},
		OTXKey:    "bad-key",
	})
	if !ok {
		t.Fatal("otx source not available")
	}
	_, err := s.Lookup(t.Context(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "Please authenticate") {
		t.Fatalf("error = %v, want the API detail", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (403 must not be retried)", requests)
	}
}

func TestOTXGatewayErrorNotRetried(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = w.Write([]byte(`<html>gateway timeout</html>`))
	}))
	defer srv.Close()

	s, ok := NewSource("otx", Options{
		Client:    srv.Client(),
		Timeout:   5 * time.Second,
		Endpoints: map[string]string{"otx": srv.URL},
		OTXKey:    "sekret",
	})
	if !ok {
		t.Fatal("otx source not available")
	}
	_, err := s.Lookup(t.Context(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "504") {
		t.Fatalf("error = %v, want HTTP 504", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (OTX must fail fast)", requests)
	}
}

func TestOTXEndpoint(t *testing.T) {
	s, ok := NewSource("otx", Options{Timeout: 2 * time.Second})
	if !ok {
		t.Fatal("otx source not available")
	}
	hs, ok := s.(*httpSource)
	if !ok {
		t.Fatalf("unexpected source type %T", s)
	}
	if defaultBase["otx"] != "https://otx.alienvault.com/api" {
		t.Fatalf("OTX base = %q", defaultBase["otx"])
	}
	got := hs.url(defaultBase["otx"], "decubate.com")
	want := "https://otx.alienvault.com/api/v1/indicators/domain/decubate.com/passive_dns"
	if got != want {
		t.Fatalf("endpoint = %q, want %q", got, want)
	}
}

func TestOTXTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	s, ok := NewSource("otx", Options{
		Client:    srv.Client(),
		Timeout:   50 * time.Millisecond,
		Endpoints: map[string]string{"otx": srv.URL},
		OTXKey:    "sekret",
	})
	if !ok {
		t.Fatal("otx source not available")
	}
	_, err := s.Lookup(t.Context(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("error = %v, want a timeout message", err)
	}
}

func TestOTXRetriesEOF(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("response writer is not a hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte(`{"passive_dns":[{"hostname":"www.example.com"}]}`))
	}))
	defer srv.Close()

	s, ok := NewSource("otx", Options{
		Client:    srv.Client(),
		Timeout:   5 * time.Second,
		Endpoints: map[string]string{"otx": srv.URL},
		OTXKey:    "sekret",
	})
	if !ok {
		t.Fatal("otx source not available")
	}
	names, err := s.Lookup(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "www.example.com" {
		t.Fatalf("names = %v", names)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

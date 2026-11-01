package passive

import (
	"net/http"
	"net/http/httptest"
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

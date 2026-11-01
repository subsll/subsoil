// Package passive collects subdomains from public, third-party data sources.
// Nothing in this package sends traffic to the target itself.
package passive

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"subsoil/internal/webx"
)

// DefaultSources are enabled unless the operator overrides --sources.
// OTX is opt-in because its passive-DNS endpoint now requires an API key.
var DefaultSources = []string{"crt.sh", "certspotter"}

// KnownSources lists every implemented source.
var KnownSources = []string{"crt.sh", "certspotter", "otx", "hackertarget"}

// Source is one passive data provider.
type Source interface {
	Name() string
	Lookup(ctx context.Context, domain string) ([]string, error)
}

// Options configures the HTTP behaviour and lets tests point sources at local
// fixture servers.
type Options struct {
	Client     *http.Client
	Timeout    time.Duration
	Endpoints  map[string]string
	OTXKey     string
	VerboseLog func(format string, args ...any)
}

type httpSource struct {
	name     string
	url      func(base, domain string) string
	parse    func([]byte) ([]string, error)
	base     string
	client   *http.Client
	timeout  time.Duration
	attempts int
	apiKey   string
	vlog     func(format string, args ...any)
}

func (s *httpSource) Name() string { return s.name }

func (s *httpSource) logf(format string, args ...any) {
	if s.vlog != nil {
		s.vlog(format, args...)
	}
}

func (s *httpSource) Lookup(ctx context.Context, domain string) ([]string, error) {
	if s.name == "otx" && s.apiKey == "" {
		return nil, errors.New("OTX requires an API key; set SUBSOIL_OTX_KEY")
	}
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	attempts := s.attempts
	if attempts <= 0 {
		attempts = 3
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		names, retry, err := s.fetch(ctx, domain)
		if err == nil {
			return names, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			break
		}
		if attempt < attempts-1 {
			s.logf("retrying: %v", err)
		}
	}
	return nil, lastErr
}

func (s *httpSource) fetch(ctx context.Context, domain string) ([]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url(s.base, domain), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", webx.RandomUA())
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.8")
	if s.name == "otx" && s.apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", s.apiKey)
	}
	s.logf("passive %s: GET %s", s.name, req.URL)

	start := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, true, err
	}
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		msg := fmt.Sprintf("%s: HTTP %d %s", s.name, resp.StatusCode, http.StatusText(resp.StatusCode))
		var apiErr struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Detail != "" {
			detail := apiErr.Detail
			if len(detail) > 300 {
				detail = detail[:300]
			}
			msg += ": " + detail
		}
		return nil, retry, errors.New(msg)
	}

	raw, err := s.parse(body)
	if err != nil {
		return nil, true, fmt.Errorf("%s: %w", s.name, err)
	}

	seen := make(map[string]struct{}, len(raw))
	var out []string
	for _, n := range raw {
		if clean, ok := Normalize(n, domain); ok {
			if _, dup := seen[clean]; dup {
				continue
			}
			seen[clean] = struct{}{}
			out = append(out, clean)
		}
	}
	sort.Strings(out)
	s.logf("passive %s: HTTP %d, %d name(s), %s", s.name, resp.StatusCode, len(out),
		time.Since(start).Round(time.Millisecond))
	return out, false, nil
}

// NewSource builds a source by name. Unknown names return nil, false.
func NewSource(name string, opts Options) (Source, bool) {
	if opts.Client == nil {
		opts.Client = webx.NewClient(opts.Timeout, false)
	}
	base := opts.Endpoints[name]
	if base == "" {
		base = defaultBase[name]
	}
	if base == "" {
		return nil, false
	}
	s := &httpSource{name: name, base: base, client: opts.Client, timeout: opts.Timeout, attempts: 3, apiKey: opts.OTXKey, vlog: opts.VerboseLog}
	switch name {
	case "crt.sh":
		s.url = func(base, domain string) string {
			q := url.Values{}
			q.Set("q", "%."+domain)
			q.Set("output", "json")
			return strings.TrimSuffix(base, "/") + "/?" + q.Encode()
		}
		s.parse = parseCrtSh
	case "certspotter":
		s.url = func(base, domain string) string {
			q := url.Values{}
			q.Set("domain", domain)
			q.Set("include_subdomains", "true")
			q.Set("expand", "dns_names")
			return strings.TrimSuffix(base, "/") + "/v1/issuances?" + q.Encode()
		}
		s.parse = parseCertSpotter
	case "otx":
		// OTX frequently returns 502/504; fail over to the next source instead
		// of retrying the same gateway for a minute.
		s.attempts = 1
		s.url = func(base, domain string) string {
			// base is https://otx.alienvault.com/api
			return strings.TrimSuffix(base, "/") + "/v1/indicators/domain/" + url.PathEscape(domain) + "/passive_dns"
		}
		s.parse = parseOTX
	case "hackertarget":
		s.url = func(base, domain string) string {
			q := url.Values{}
			q.Set("q", domain)
			return strings.TrimSuffix(base, "/") + "/hostsearch/?" + q.Encode()
		}
		s.parse = parseHackerTarget
	default:
		return nil, false
	}
	return s, true
}

var defaultBase = map[string]string{
	"crt.sh":       "https://crt.sh",
	"certspotter":  "https://api.certspotter.com",
	"otx":          "https://otx.alienvault.com/api",
	"hackertarget": "https://api.hackertarget.com",
}

func parseCrtSh(body []byte) ([]string, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("bad crt.sh response: %w", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, strings.Split(r.NameValue, "\n")...)
		out = append(out, r.CommonName)
	}
	return out, nil
}

func parseCertSpotter(body []byte) ([]string, error) {
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("bad certspotter response: %w", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out, nil
}

func parseOTX(body []byte) ([]string, error) {
	var doc struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("bad OTX response: %w", err)
	}
	out := make([]string, 0, len(doc.PassiveDNS))
	for _, r := range doc.PassiveDNS {
		out = append(out, r.Hostname)
	}
	return out, nil
}

func parseHackerTarget(body []byte) ([]string, error) {
	r := csv.NewReader(bytes.NewReader(body))
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("bad hackertarget response: %w", err)
	}
	var out []string
	for _, row := range rows {
		if len(row) > 0 {
			out = append(out, row[0])
		}
	}
	return out, nil
}

// Normalize turns a certificate/PDNS name into a clean subdomain of domain.
// Wildcards are stripped; the apex, invalid labels and lookalikes are dropped.
func Normalize(name, domain string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSpace(name)
	if name == "" || name == domain {
		return "", false
	}
	if !strings.HasSuffix(name, "."+domain) {
		return "", false
	}
	if !validName(name) {
		return "", false
	}
	return name, true
}

func validName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for _, l := range strings.Split(name, ".") {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// ErrNoSources is returned by Resolve when nothing is configured.
var ErrNoSources = errors.New("passive: no sources configured")

// Resolve runs the configured sources concurrently. A source failure is
// returned alongside any names the other sources produced.
func Resolve(ctx context.Context, domain string, names []string, opts Options) (map[string][]string, map[string]error) {
	type result struct {
		name  string
		names []string
		err   error
	}
	ch := make(chan result, len(names))
	run := 0
	for _, n := range names {
		s, ok := NewSource(n, opts)
		if !ok {
			continue
		}
		run++
		go func(s Source) {
			got, err := s.Lookup(ctx, domain)
			ch <- result{name: s.Name(), names: got, err: err}
		}(s)
	}
	if run == 0 {
		return nil, map[string]error{"": ErrNoSources}
	}

	out := make(map[string][]string, run)
	errs := make(map[string]error)
	for i := 0; i < run; i++ {
		r := <-ch
		if r.err != nil {
			errs[r.name] = r.err
			continue
		}
		out[r.name] = r.names
	}
	return out, errs
}

// Package probe performs a single, cheap HTTP(S) request per host to identify
// web portals. It deliberately does not crawl.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"subsoil/internal/model"
	"subsoil/internal/webx"
)

// Options configures a probe.
type Options struct {
	Timeout    time.Duration
	Insecure   bool
	Capture    bool
	BodyDir    string
	MaxBody    int64
	VerboseLog func(format string, args ...any)
}

func (o Options) logf(format string, args ...any) {
	if o.VerboseLog != nil {
		o.VerboseLog(format, args...)
	}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Probe tries HTTPS first, then plain HTTP. The returned value always has a
// Time and SHA256 set; Error explains a total failure.
func Probe(ctx context.Context, host string, opt Options) model.HTTP {
	if opt.MaxBody <= 0 {
		opt.MaxBody = 2 << 20
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 8 * time.Second
	}

	res := model.HTTP{Host: host, Time: time.Now().UTC()}
	var errs []string
	for _, scheme := range []string{"https", "http"} {
		if ctx.Err() != nil {
			res.Error = ctx.Err().Error()
			return res
		}
		r, err := attempt(ctx, scheme, host, opt)
		if err == nil {
			res = r
			res.Host = host
			return res
		}
		opt.logf("probe %s: %s failed: %v", host, scheme, err)
		errs = append(errs, fmt.Sprintf("%s: %v", scheme, err))
	}
	res.Error = strings.Join(errs, "; ")
	return res
}

func attempt(ctx context.Context, scheme, host string, opt Options) (model.HTTP, error) {
	res := model.HTTP{
		Host:   host,
		Scheme: scheme,
		URL:    scheme + "://" + host + "/",
		Time:   time.Now().UTC(),
	}

	client := webx.NewClient(opt.Timeout, opt.Insecure)
	var redirects []string
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirects = append(redirects, req.URL.String())
		if len(via) >= 4 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, res.URL, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", webx.RandomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode
	res.URL = resp.Request.URL.String()
	res.Server = resp.Header.Get("Server")
	res.ContentType = resp.Header.Get("Content-Type")
	res.Redirects = redirects

	body, err := io.ReadAll(io.LimitReader(resp.Body, opt.MaxBody+1))
	if err != nil {
		return res, err
	}
	truncated := int64(len(body)) > opt.MaxBody
	if truncated {
		body = body[:opt.MaxBody]
	}
	sum := sha256.Sum256(body)
	res.BodySHA256 = hex.EncodeToString(sum[:])
	res.BodyLen = int64(len(body))

	if opt.Capture && len(body) > 0 && opt.BodyDir != "" {
		name := safeName(host) + "-" + res.BodySHA256[:12] + ".body"
		if err := os.MkdirAll(opt.BodyDir, 0o755); err == nil {
			path := filepath.Join(opt.BodyDir, name)
			if err := os.WriteFile(path, body, 0o644); err == nil {
				res.BodyFile = filepath.Join("bodies", name)
			}
		}
	}

	res.Title = extractTitle(body)
	opt.logf("probe %s -> %d %s %q", res.URL, res.Status, res.Server, res.Title)

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		res.TLS = &model.TLS{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			NotBefore: cert.NotBefore.UTC(),
			NotAfter:  cert.NotAfter.UTC(),
			DNSNames:  append([]string(nil), cert.DNSNames...),
		}
	}
	return res, nil
}

func extractTitle(body []byte) string {
	if len(body) > 64*1024 {
		body = body[:64*1024]
	}
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := html.UnescapeString(string(m[1]))
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 200 {
		title = title[:200] + "…"
	}
	return title
}

func safeName(host string) string {
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

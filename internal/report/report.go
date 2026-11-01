// Package report renders scan results as terminal output, JSON, Markdown,
// HTML and CSV, and writes a checksum manifest for every artefact.
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	texttemplate "text/template"
	"time"

	"subsoil/internal/model"
)

var mdFuncs = texttemplate.FuncMap{
	"join":     strings.Join,
	"dash":     dash,
	"addrs":    hostAddrs,
	"status":   hostStatus,
	"datetime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"dur":      fmtDuration,
	"rrvalue":  rrValue,
	"label":    recordLabel,
	"has":      func(s []string) bool { return len(s) > 0 },
	"pct":      pct,
	"rrvalues": rrValues,
	"resolved": resolvedCount,
	"axfrok":   axfrOK,
	"md":       mdEscape,
}

// Write renders the requested formats into dir and returns the file list.
func Write(res *model.Result, dir string, formats []string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var files []string
	add := func(name string) { files = append(files, name) }

	// Machine-readable host lists are always produced.
	var sub strings.Builder
	for _, h := range res.Hosts {
		sub.WriteString(h.Name)
		sub.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "subdomains.txt"), []byte(sub.String()), 0o644); err != nil {
		return nil, err
	}
	add("subdomains.txt")

	if err := writeHostsCSV(filepath.Join(dir, "hosts.csv"), res.Hosts); err != nil {
		return nil, err
	}
	add("hosts.csv")

	if res.Evidence.FileSHA256 != "" {
		line := fmt.Sprintf("%s  evidence.jsonl\n", res.Evidence.FileSHA256)
		if err := os.WriteFile(filepath.Join(dir, "evidence.jsonl.sha256"), []byte(line), 0o644); err != nil {
			return nil, err
		}
		add("evidence.jsonl.sha256")
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence.jsonl")); err == nil {
		add("evidence.jsonl")
	}

	for _, f := range formats {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "text":
			var buf bytes.Buffer
			RenderText(&buf, res, false)
			if err := os.WriteFile(filepath.Join(dir, "report.txt"), buf.Bytes(), 0o644); err != nil {
				return nil, err
			}
			add("report.txt")
		case "json":
			b, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				return nil, err
			}
			b = append(b, '\n')
			if err := os.WriteFile(filepath.Join(dir, "report.json"), b, 0o644); err != nil {
				return nil, err
			}
			add("report.json")
		case "md", "markdown":
			var buf bytes.Buffer
			if err := renderMarkdown(&buf, res); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(dir, "report.md"), tidyBlanks(buf.Bytes()), 0o644); err != nil {
				return nil, err
			}
			add("report.md")
		case "html":
			var buf bytes.Buffer
			if err := renderHTML(&buf, res); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(dir, "report.html"), buf.Bytes(), 0o644); err != nil {
				return nil, err
			}
			add("report.html")
		default:
			return nil, fmt.Errorf("unknown output format %q (want text, json, md, html)", f)
		}
	}

	sort.Strings(files)
	sums, err := checksums(dir, files)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		return nil, err
	}
	files = append(files, "SHA256SUMS")
	return files, nil
}

func checksums(dir string, files []string) (string, error) {
	var b strings.Builder
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return b.String(), nil
}

func writeHostsCSV(path string, hosts []model.Host) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{"name", "resolved", "rcode", "ipv4", "ipv6", "ips_hidden", "cname", "sources", "sha256"}); err != nil {
		return err
	}
	for _, h := range hosts {
		row := []string{
			h.Name, fmt.Sprintf("%t", h.Resolved), h.RCode,
			strings.Join(h.IPs, " "), strings.Join(h.AAAA, " "), fmt.Sprintf("%t", h.IPsHidden), h.CNAME,
			strings.Join(h.Sources, " "), h.Hash,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// RenderText writes the human summary. Colour is opt-in.
func RenderText(w io.Writer, res *model.Result, color bool) {
	s := styler{on: color}
	line := func(format string, args ...any) { fmt.Fprintf(w, format+"\n", args...) }

	line("")
	line("  %s", s.bold("Subsoil "+res.Version)+s.dim("  ·  low-observable DNS reconnaissance"))
	line("")
	line("  %s  %s", s.dim("target     "), res.Domain)
	line("  %s  %s  %s", s.dim("started    "), res.Started.UTC().Format("2006-01-02 15:04:05 UTC"),
		s.dim("("+fmtDuration(res.DurationMS)+")"))
	line("  %s  %s", s.dim("resolvers  "), strings.Join(res.Resolvers, ", "))
	mode := "standard"
	if res.Options.Passive {
		mode = "passive-only (no DNS packets sent)"
	}
	line("  %s  %s", s.dim("mode       "), mode)
	if len(res.Options.Sources) > 0 {
		line("  %s  %s", s.dim("sources    "), strings.Join(res.Options.Sources, ", "))
	}
	if res.Options.Brute {
		line("  %s  %d words, %d workers, %d qps", s.dim("brute      "),
			res.Options.Words, res.Options.Workers, res.Options.QPS)
	}

	// Infrastructure.
	line("")
	section(w, s, "Infrastructure")
	printed := 0
	for _, rs := range res.Records {
		if len(rs.RRs) == 0 {
			continue
		}
		label := recordLabel(rs)
		vals := make([]string, 0, len(rs.RRs))
		for _, rr := range rs.RRs {
			vals = append(vals, rrValue(rs.Type, rr))
		}
		line("  %-10s %s", label, wrap(strings.Join(vals, ", "), 100, "             "))
		printed++
	}
	if printed == 0 {
		if res.Options.Passive {
			line("  %s", s.dim("(skipped in passive-only mode)"))
		} else {
			line("  %s", s.dim("(no records returned)"))
		}
	}

	// Subdomains.
	resolved := 0
	for _, h := range res.Hosts {
		if h.Resolved {
			resolved++
		}
	}
	line("")
	section(w, s, fmt.Sprintf("Subdomains  %d found · %d resolved", len(res.Hosts), resolved))
	if !res.Options.ResolveIPs {
		line("  %s", s.dim("IP lookup disabled: addresses are hidden"))
	}
	if len(res.Hosts) == 0 {
		line("  %s", s.dim("(none)"))
	} else {
		nameW, addrW := 4, 10
		for _, h := range res.Hosts {
			if n := len(h.Name); n > nameW {
				nameW = n
			}
			if n := len(displayAddrs(h)); n > addrW {
				addrW = n
			}
		}
		if nameW > 46 {
			nameW = 46
		}
		if addrW > 44 {
			addrW = 44
		}
		line("  %s %s %s", s.dim(pad("NAME", nameW)), s.dim(pad("ADDRESS", addrW)), s.dim("SOURCES"))
		max := len(res.Hosts)
		if max > 80 {
			max = 80
		}
		for _, h := range res.Hosts[:max] {
			addr := displayAddrs(h)
			line("  %s %s %s", pad(truncate(h.Name, nameW), nameW), pad(truncate(addr, addrW), addrW),
				s.dim(strings.Join(h.Sources, ", ")))
		}
		if len(res.Hosts) > max {
			line("  %s", s.dim(fmt.Sprintf("… %d more in report.md / report.json", len(res.Hosts)-max)))
		}
	}

	// Wildcard.
	if !res.Options.Passive {
		line("")
		section(w, s, "Wildcard DNS")
		if res.Wildcard.Enabled {
			line("  %s detected: %s", s.bold("!"), strings.Join(res.Wildcard.IPs, ", "))
			if len(res.Wildcard.CNAMEs) > 0 {
				line("    cnames: %s", strings.Join(res.Wildcard.CNAMEs, ", "))
			}
			line("    %d brute-force result(s) filtered as wildcard answers", res.Wildcard.Filtered)
		} else {
			line("  %s", s.dim("not detected"))
		}
	}

	// Zone transfer.
	if res.Options.AXFR {
		line("")
		section(w, s, "Zone transfer (AXFR)")
		if len(res.AXFR) == 0 {
			line("  %s", s.dim("no nameserver addresses available"))
		}
		for i, z := range res.AXFR {
			if i >= 10 {
				break
			}
			if z.OK {
				line("  %s %s  %s", s.good("SUCCESS"), z.NS, s.dim(z.Address))
				line("    %d records · sha256 %s", len(z.Records), z.RecordsSHA256)
			} else {
				line("  %-8s %s  %s", s.dim("refused"), z.NS, s.dim(z.Error))
			}
		}
	}

	// SRV.
	if res.Options.SRV && len(res.SRV) > 0 {
		line("")
		section(w, s, "Service records (SRV)")
		for _, e := range res.SRV {
			line("  %-32s %s:%d  %s", e.Name, e.Target, e.Port, s.dim(fmt.Sprintf("prio %d weight %d", e.Priority, e.Weight)))
		}
	}

	// PTR.
	if res.Options.PTR && len(res.PTR) > 0 {
		line("")
		section(w, s, "Reverse DNS (PTR)")
		for _, e := range res.PTR {
			line("  %-40s %s", e.IP, strings.Join(e.Names, ", "))
		}
	}

	// HTTP.
	if res.Options.HTTP {
		line("")
		section(w, s, fmt.Sprintf("Web services  %d probed", res.Stats.HTTPProbes))
		if len(res.HTTP) == 0 {
			line("  %s", s.dim("(none)"))
		}
		for i, h := range res.HTTP {
			if i >= 40 {
				line("  %s", s.dim(fmt.Sprintf("… %d more", len(res.HTTP)-40)))
				break
			}
			if h.Error != "" {
				line("  %-30s %s", h.Host, s.dim(h.Error))
				continue
			}
			tlsNote := ""
			if h.TLS != nil {
				tlsNote = " · " + s.dim(h.TLS.Issuer)
			}
			line("  %-30s %s  %-10s %s%s", h.Host, s.good(fmt.Sprintf("%d", h.Status)),
				truncate(h.Server, 10), quoteTitle(h.Title), tlsNote)
		}
	}

	// Evidence.
	line("")
	section(w, s, "Evidence")
	line("  %-12s %d records, hash-chained (seq 1..%d)", s.dim("records"), res.Evidence.Records, res.Evidence.Records)
	line("  %-12s %s", s.dim("chain root"), res.Evidence.RootSHA256)
	line("  %-12s %s", s.dim("file sha256"), res.Evidence.FileSHA256)
	line("  %-12s %s", s.dim("evidence"), res.Evidence.File)
	line("  %-12s subsoil verify %s", s.dim("verify"), filepath.Base(res.Evidence.File))

	if len(res.Errors) > 0 {
		line("")
		section(w, s, "Errors / warnings")
		for i, e := range res.Errors {
			if i >= 8 {
				line("  %s", s.dim(fmt.Sprintf("… %d more", len(res.Errors)-8)))
				break
			}
			line("  %s %s", s.warn("!"), e)
		}
	}

	line("")
	line("  %s", s.dim("Use only against systems you own or are explicitly authorised to test."))
	line("")
}

func section(w io.Writer, s styler, title string) {
	fmt.Fprintf(w, "  %s\n", s.bold(title))
	fmt.Fprintf(w, "  %s\n", s.dim(strings.Repeat("─", min(len(title)+4, 72))))
}

type styler struct{ on bool }

func (s styler) wrap(code, x string) string {
	if !s.on {
		return x
	}
	return code + x + "\x1b[0m"
}
func (s styler) bold(x string) string { return s.wrap("\x1b[1m", x) }
func (s styler) dim(x string) string  { return s.wrap("\x1b[2m", x) }
func (s styler) good(x string) string { return s.wrap("\x1b[32m", x) }
func (s styler) warn(x string) string { return s.wrap("\x1b[33m", x) }

func recordLabel(rs model.RecordSet) string {
	if strings.HasPrefix(rs.Name, "_dmarc.") {
		return "DMARC"
	}
	if strings.HasPrefix(rs.Name, "_domainkey.") {
		return "DKIM"
	}
	return rs.Type
}

func rrValue(typ, rr string) string {
	// canonical RRs are tab separated; tolerate space separated input too.
	for _, marker := range []string{"\tIN\t" + typ + "\t", " IN " + typ + " "} {
		if i := strings.Index(rr, marker); i >= 0 {
			return cleanText(strings.TrimSpace(rr[i+len(marker):]))
		}
	}
	return cleanText(rr)
}

// cleanText strips control characters so hostile TXT records cannot inject
// terminal escapes or new Markdown structure into a report.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func displayAddrs(h model.Host) string {
	if a := hostAddrs(h); a != "—" {
		return a
	}
	if !h.Resolved {
		return "unresolved"
	}
	return "—"
}

func hostAddrs(h model.Host) string {
	if h.IPsHidden {
		if h.CNAME != "" {
			return "hidden, cname:" + cleanText(h.CNAME)
		}
		return "hidden"
	}
	var parts []string
	parts = append(parts, h.IPs...)
	parts = append(parts, h.AAAA...)
	if h.CNAME != "" {
		parts = append(parts, "cname:"+cleanText(h.CNAME))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, ", ")
}

func hostStatus(h model.Host) string {
	if h.IPsHidden && !h.Resolved {
		return "not checked"
	}
	if h.Resolved {
		return "resolved"
	}
	if h.RCode != "" && h.RCode != "NOERROR" {
		return strings.ToLower(h.RCode)
	}
	return "unresolved"
}

func fmtDuration(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if d < time.Second {
		return d.String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func pct(part, total int) string {
	if total == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.0f%%", float64(part)*100/float64(total))
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func quoteTitle(t string) string {
	if t == "" {
		return ""
	}
	t = cleanText(t)
	if len(t) > 40 {
		t = t[:40] + "…"
	}
	return `"` + t + `"`
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// wrap soft-wraps a comma separated list onto contiguous lines.
func wrap(s string, width int, indent string) string {
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	cur := 0
	parts := strings.Split(s, ", ")
	for i, p := range parts {
		if cur > 0 && cur+len(p)+2 > width {
			b.WriteString(",\n" + indent)
			cur = 0
		} else if i > 0 {
			b.WriteString(", ")
			cur += 2
		}
		b.WriteString(p)
		cur += len(p)
	}
	return b.String()
}

// tidyBlanks collapses runs of blank lines so template whitespace does not
// leave holes in the rendered Markdown.
func tidyBlanks(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(lines))
	blank := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}

func renderMarkdown(w io.Writer, res *model.Result) error {
	t, err := texttemplate.New("md").Funcs(mdFuncs).Parse(mdTemplate)
	if err != nil {
		return err
	}
	return t.Execute(w, res)
}

func rrValues(rs model.RecordSet) string {
	vals := make([]string, 0, len(rs.RRs))
	for _, rr := range rs.RRs {
		vals = append(vals, rrValue(rs.Type, rr))
	}
	return mdEscape(strings.Join(vals, ", "))
}

func resolvedCount(hs []model.Host) int {
	n := 0
	for _, h := range hs {
		if h.Resolved {
			n++
		}
	}
	return n
}

func axfrOK(zs []model.AXFR) int {
	n := 0
	for _, z := range zs {
		if z.OK {
			n++
		}
	}
	return n
}

func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func safeURL(s string) template.URL {
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
		return template.URL(s) //nolint:gosec // scheme-checked above
	}
	return template.URL("#")
}

func renderHTML(w io.Writer, res *model.Result) error {
	t, err := template.New("html").Funcs(template.FuncMap{
		"join": strings.Join, "dash": dash, "addrs": hostAddrs, "status": hostStatus,
		"datetime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
		"dur":      fmtDuration, "rrvalue": rrValue, "label": recordLabel, "has": func(s []string) bool { return len(s) > 0 },
		"pct": pct, "safeurl": safeURL, "rrvalues": rrValues,
		"resolved": resolvedCount, "axfrok": axfrOK,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return t.Execute(w, res)
}

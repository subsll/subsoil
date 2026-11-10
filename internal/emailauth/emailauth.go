// Package emailauth evaluates SPF, DKIM and DMARC DNS records and produces a
// transparent configuration-hygiene score. It does not send or authenticate
// mail, and the score is not a deliverability metric.
package emailauth

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/subsll/subsoil/internal/model"
)

const (
	SPFMaxScore   = 35
	DKIMmaxScore  = 25
	DMARCMaxScore = 40
	MaxScore      = SPFMaxScore + DKIMmaxScore + DMARCMaxScore
	selectorLimit = 32
)

// DefaultSelectors is the conservative set of DKIM selectors checked when no
// custom selector list is supplied. DKIM selectors are arbitrary, so a missing
// key at these names does not prove the domain has no DKIM.
var DefaultSelectors = []string{
	"default", "google", "selector1", "selector2", "s1", "s2",
	"k1", "mail", "dkim", "smtp", "mandrill", "zoho", "protonmail", "cm",
}

// SelectorObservation is the result of one selector TXT lookup.
type SelectorObservation struct {
	Selector string
	Name     string
	TXT      []string
	CNAME    []string
	RCode    string
	Error    string
}

var selectorLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// CleanSelectors normalises a selector list, applies the defaults when empty
// and rejects names that cannot be used as DNS labels.
func CleanSelectors(input []string) ([]string, error) {
	if len(input) == 0 {
		return append([]string(nil), DefaultSelectors...), nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range input {
		for _, part := range strings.Split(raw, ",") {
			selector := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(part), "."))
			if selector == "" {
				continue
			}
			if len(selector) > 128 {
				return nil, fmt.Errorf("DKIM selector %q is too long", selector)
			}
			for _, label := range strings.Split(selector, ".") {
				if !selectorLabelRe.MatchString(label) {
					return nil, fmt.Errorf("invalid DKIM selector %q", selector)
				}
			}
			if !seen[selector] {
				seen[selector] = true
				out = append(out, selector)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no DKIM selectors supplied")
	}
	if len(out) > selectorLimit {
		return nil, fmt.Errorf("too many DKIM selectors (%d); limit is %d", len(out), selectorLimit)
	}
	return out, nil
}

// Analyze scores the supplied records. SelectorOrder is preserved in the
// output; all other values are deterministic.
func Analyze(domain string, spfValues, dmarcValues []string, selectors []SelectorObservation) *model.EmailAnalysis {
	stripped := make([]string, 0, len(selectors))
	for _, s := range selectors {
		stripped = append(stripped, s.Selector)
	}
	a := &model.EmailAnalysis{
		MaxScore: MaxScore,
		SPF:      analyzeSPF(spfValues),
		DKIM:     analyzeDKIM(stripped, selectors),
		DMARC:    analyzeDMARC(dmarcValues),
	}
	a.Score = a.SPF.Score + a.DKIM.Score + a.DMARC.Score
	a.Grade, a.Verdict = gradeFor(a.Score)
	a.Summary = summarize(domain, a)
	a.Issues = collectIssues(a)
	return a
}

func analyzeSPF(values []string) model.EmailSPF {
	res := model.EmailSPF{MaxScore: SPFMaxScore}
	var records []string
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(strings.ToLower(trimmed), "v=spf1") {
			records = append(records, trimmed)
		}
	}
	res.Records = len(records)
	if len(records) == 0 {
		res.Issues = append(res.Issues, "No SPF record found at the domain apex.")
		return res
	}
	res.Present = true
	res.Record = strings.Join(records, " | ")
	if len(records) > 1 {
		res.Issues = append(res.Issues, "Multiple SPF records exist; receivers will treat SPF as permerror.")
		return res
	}
	record := records[0]
	fields := strings.Fields(record)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		res.Issues = append(res.Issues, "SPF record does not begin with v=spf1.")
		return res
	}
	res.Valid = true
	// A single valid record is worth 15 points: presence plus syntax.
	res.Score = 15

	lookups := 0
	allSeen := false
	for _, field := range fields[1:] {
		qualifier, mechanism := splitQualifier(strings.ToLower(field))
		if mechanism == "all" {
			if qualifier == "" {
				qualifier = "+"
			}
			res.All = qualifier + "all"
			allSeen = true
			switch qualifier {
			case "-":
				res.Score += 15
			case "~":
				res.Score += 12
			case "?":
				res.Score += 6
			case "+":
				res.Issues = append(res.Issues, "SPF ends in +all, which authorises every sender; use -all or ~all.")
			}
			break
		}
		if spfNeedsLookup(mechanism) {
			lookups++
		}
		if mechanism == "ptr" || strings.HasPrefix(mechanism, "ptr:") {
			res.Issues = append(res.Issues, "SPF uses the deprecated ptr mechanism; it is slow and unreliable.")
		}
	}
	res.DNSLookups = lookups
	if !allSeen {
		res.Issues = append(res.Issues, "SPF has no all mechanism; the policy is incomplete.")
	}
	if lookups > 10 {
		res.Issues = append(res.Issues, fmt.Sprintf("SPF declares %d DNS-lookup terms; RFC 7208 permits at most 10.", lookups))
	} else {
		res.Score += 5
	}
	if res.Score > res.MaxScore {
		res.Score = res.MaxScore
	}
	return res
}

func splitQualifier(term string) (qualifier, mechanism string) {
	if term == "" {
		return "", ""
	}
	switch term[0] {
	case '+', '-', '~', '?':
		return string(term[0]), term[1:]
	}
	return "", term
}

func spfNeedsLookup(mechanism string) bool {
	for _, prefix := range []string{"include:", "exists:", "redirect=", "a:", "mx:", "ptr:"} {
		if strings.HasPrefix(mechanism, prefix) {
			return true
		}
	}
	switch mechanism {
	case "a", "mx", "ptr":
		return true
	}
	if strings.HasPrefix(mechanism, "a/") || strings.HasPrefix(mechanism, "mx/") {
		return true
	}
	return false
}

func analyzeDKIM(selectors []string, observations []SelectorObservation) model.EmailDKIM {
	res := model.EmailDKIM{
		MaxScore:         DKIMmaxScore,
		SelectorsChecked: append([]string(nil), selectors...),
	}
	if len(observations) == 0 {
		res.Issues = append(res.Issues, "No DKIM selectors were checked.")
		return res
	}
	best := 0
	var revokedSelectors, invalidSelectors, failedSelectors, cnameSelectors []string
	for _, obs := range observations {
		item := model.DKIMSelector{
			Selector: obs.Selector,
			Name:     obs.Name,
			Status:   "not-found",
		}
		if len(obs.CNAME) > 0 {
			item.CNAME = strings.Join(obs.CNAME, ", ")
		}
		if obs.Error != "" {
			item.Status = "error"
			item.Issue = cleanOneLine(obs.Error)
			failedSelectors = append(failedSelectors, obs.Selector)
			res.Selectors = append(res.Selectors, item)
			continue
		}
		if len(obs.TXT) == 0 && len(obs.CNAME) == 0 {
			res.Selectors = append(res.Selectors, item)
			continue
		}
		res.Configured = true
		res.FoundSelectors = append(res.FoundSelectors, obs.Selector)
		valid, revoked, keyType, record, issues := inspectDKIMTXT(obs.TXT)
		item.Record = truncateText(record, 500)
		item.KeyType = keyType
		switch {
		case valid:
			item.Status = "valid"
			item.Valid = true
			res.ValidSelectors = append(res.ValidSelectors, obs.Selector)
			res.Valid = true
			if best < DKIMmaxScore {
				best = DKIMmaxScore
			}
		case len(obs.TXT) == 0: // CNAME-only provider alias.
			item.Status = "cname-only"
			cnameSelectors = append(cnameSelectors, obs.Selector)
			if best < 15 {
				best = 15
			}
		case revoked:
			item.Status = "revoked"
			item.Issue = "public key is empty (revoked)"
			revokedSelectors = append(revokedSelectors, obs.Selector)
		default:
			item.Status = "invalid"
			if len(issues) > 0 {
				item.Issue = strings.Join(issues, "; ")
			} else {
				item.Issue = "no valid DKIM public key"
			}
			invalidSelectors = append(invalidSelectors, obs.Selector)
		}
		res.Selectors = append(res.Selectors, item)
	}
	res.ValidSelectors = sortUnique(res.ValidSelectors)
	res.FoundSelectors = sortUnique(res.FoundSelectors)
	res.Score = best
	if len(failedSelectors) > 0 {
		res.Issues = append(res.Issues, fmt.Sprintf("DKIM lookups failed for %d selector(s): %s.", len(failedSelectors), compactSelectors(failedSelectors)))
	}
	if len(revokedSelectors) > 0 {
		res.Issues = append(res.Issues, fmt.Sprintf("Revoked DKIM key (p= empty) at %d selector(s): %s.", len(revokedSelectors), compactSelectors(revokedSelectors)))
	}
	if len(invalidSelectors) > 0 {
		res.Issues = append(res.Issues, fmt.Sprintf("Invalid DKIM key at %d selector(s): %s.", len(invalidSelectors), compactSelectors(invalidSelectors)))
	}
	if len(cnameSelectors) > 0 && !res.Valid {
		res.Issues = append(res.Issues, fmt.Sprintf("DKIM is delegated by CNAME at %d selector(s), but no provider TXT key was returned: %s.", len(cnameSelectors), compactSelectors(cnameSelectors)))
	}
	if !res.Valid {
		if res.Configured {
			res.Issues = append(res.Issues, "No usable DKIM public key was validated; confirm the provider selector with --dkim-selectors.")
		} else {
			res.Issues = append(res.Issues, "No DKIM key found at the common selectors; use --dkim-selectors to check a provider-specific selector.")
		}
	}
	return res
}

func compactSelectors(selectors []string) string {
	const maxShown = 5
	if len(selectors) <= maxShown {
		return strings.Join(selectors, ", ")
	}
	return strings.Join(selectors[:maxShown], ", ") + fmt.Sprintf(" (+%d more)", len(selectors)-maxShown)
}

func inspectDKIMTXT(values []string) (valid, revoked bool, keyType, record string, issues []string) {
	for _, raw := range values {
		recordCandidate := strings.TrimSpace(raw)
		if recordCandidate == "" {
			continue
		}
		record = recordCandidate
		tags, parseIssues := parseTags(recordCandidate)
		issues = append(issues, parseIssues...)
		version := strings.TrimSpace(tags["v"])
		if version != "" && !strings.EqualFold(version, "DKIM1") {
			issues = append(issues, "v= must be DKIM1")
			continue
		}
		p, ok := tags["p"]
		if !ok {
			issues = append(issues, "missing p= public-key tag")
			continue
		}
		if p == "" {
			revoked = true
			continue
		}
		compact := strings.Join(strings.Fields(strings.Trim(p, `"'`)), "")
		decoded, err := base64.StdEncoding.DecodeString(compact)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(compact)
		}
		if err != nil || len(decoded) < 16 {
			issues = append(issues, "p= is not a usable base64 public key")
			continue
		}
		valid = true
		keyType = strings.ToLower(strings.TrimSpace(tags["k"]))
		if keyType == "" {
			keyType = "rsa"
		}
		return true, false, keyType, record, issues
	}
	return false, revoked, "", record, issues
}

func analyzeDMARC(values []string) model.EmailDMARC {
	res := model.EmailDMARC{MaxScore: DMARCMaxScore, Percent: 100}
	var candidates []string
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		low := strings.ToLower(trimmed)
		if trimmed != "" && (strings.Contains(low, "v=dmarc1") || strings.Contains(low, "p=")) {
			candidates = append(candidates, trimmed)
		}
	}
	res.Records = len(candidates)
	if len(candidates) == 0 {
		res.Issues = append(res.Issues, "No DMARC record found at _dmarc; publishing one is the highest-impact email improvement.")
		return res
	}
	res.Present = true
	res.Record = strings.Join(candidates, " | ")
	if len(candidates) > 1 {
		res.Issues = append(res.Issues, "Multiple DMARC records exist; receivers will ignore the policy.")
		return res
	}
	record := candidates[0]
	first := strings.ToLower(strings.TrimSpace(strings.SplitN(record, ";", 2)[0]))
	if first != "v=dmarc1" {
		res.Issues = append(res.Issues, "DMARC record must begin with v=DMARC1.")
		return res
	}
	tags, parseIssues := parseTags(record)
	res.Issues = append(res.Issues, parseIssues...)
	version := strings.TrimSpace(tags["v"])
	if !strings.EqualFold(version, "DMARC1") {
		res.Issues = append(res.Issues, "DMARC version tag is invalid.")
		return res
	}
	policy := strings.ToLower(strings.TrimSpace(tags["p"]))
	switch policy {
	case "reject", "quarantine", "none":
	default:
		res.Issues = append(res.Issues, "DMARC p= must be one of none, quarantine or reject.")
		return res
	}
	res.Valid = true
	res.Policy = policy
	res.SubdomainPolicy = strings.ToLower(strings.TrimSpace(tags["sp"]))
	res.Reporting = strings.TrimSpace(tags["rua"]) != ""
	adkim := strings.ToLower(strings.TrimSpace(tags["adkim"]))
	aspf := strings.ToLower(strings.TrimSpace(tags["aspf"]))
	res.Strict = adkim == "s" || aspf == "s"
	if pct := strings.TrimSpace(tags["pct"]); pct != "" {
		if n, err := strconv.Atoi(pct); err == nil && n >= 0 && n <= 100 {
			res.Percent = n
			if n < 100 {
				res.Issues = append(res.Issues, fmt.Sprintf("DMARC policy applies to only %d%% of mail (pct=%d).", n, n))
			}
		} else {
			res.Issues = append(res.Issues, "DMARC pct= must be an integer from 0 to 100.")
		}
	}

	res.Score = 10
	switch policy {
	case "reject":
		res.Score += 15
	case "quarantine":
		res.Score += 10
	case "none":
		res.Score += 3
		res.Issues = append(res.Issues, "DMARC policy is monitor-only (p=none); quarantine or reject is stronger.")
	}
	if res.Reporting {
		res.Score += 10
	} else {
		res.Issues = append(res.Issues, "DMARC has no rua= reporting address; failures will be invisible.")
	}
	if res.Strict {
		res.Score += 5
	} else {
		res.Issues = append(res.Issues, "DMARC alignment is relaxed; adkim=s or aspf=s is stricter.")
	}
	if res.Score > res.MaxScore {
		res.Score = res.MaxScore
	}
	return res
}

func parseTags(record string) (map[string]string, []string) {
	tags := map[string]string{}
	var issues []string
	seen := map[string]bool{}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			issues = append(issues, fmt.Sprintf("malformed tag %q", truncateText(part, 80)))
			continue
		}
		if seen[key] {
			issues = append(issues, fmt.Sprintf("duplicate %s= tag", key))
			continue
		}
		seen[key] = true
		tags[key] = value
	}
	return tags, issues
}

func gradeFor(score int) (grade, verdict string) {
	switch {
	case score >= 90:
		return "A", "strong"
	case score >= 75:
		return "B", "good"
	case score >= 60:
		return "C", "fair"
	case score >= 40:
		return "D", "weak"
	default:
		return "F", "poor"
	}
}

func summarize(domain string, a *model.EmailAnalysis) string {
	spf := "missing"
	if a.SPF.Valid {
		spf = "present"
	}
	dkim := "not found"
	if a.DKIM.Valid {
		dkim = "present"
	} else if a.DKIM.Configured {
		dkim = "configured but unverified"
	}
	dmarc := "missing"
	if a.DMARC.Valid {
		dmarc = "p=" + a.DMARC.Policy
	}
	base := fmt.Sprintf("%s email authentication: SPF %s, DKIM %s, DMARC %s.", strings.TrimSpace(domain), spf, dkim, dmarc)
	switch a.Grade {
	case "A":
		return base + " Strong configuration; no material gaps detected."
	case "B":
		return base + " Good configuration; review the remaining gaps."
	case "C":
		return base + " Partial configuration; enforcement is inconsistent."
	case "D":
		return base + " Weak configuration; important controls are missing or unenforced."
	default:
		return base + " Poor configuration; email authentication is effectively absent or broken."
	}
}

func collectIssues(a *model.EmailAnalysis) []string {
	var out []string
	for _, issue := range a.SPF.Issues {
		out = append(out, "SPF: "+issue)
	}
	for _, issue := range a.DKIM.Issues {
		out = append(out, "DKIM: "+issue)
	}
	for _, issue := range a.DMARC.Issues {
		out = append(out, "DMARC: "+issue)
	}
	return out
}

func truncateText(s string, n int) string {
	s = cleanOneLine(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func cleanOneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func sortUnique(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

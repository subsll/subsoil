package scan

import (
	"context"
	"fmt"
	"strings"

	"github.com/subsll/subsoil/internal/dnsx"
	"github.com/subsll/subsoil/internal/emailauth"
	"github.com/subsll/subsoil/internal/evidence"
	"github.com/subsll/subsoil/internal/model"

	"github.com/miekg/dns"
)

// runEmailAnalysis reuses the baseline SPF/DMARC answers and performs the
// selector-specific DKIM TXT lookups required by --email-analysis.
func runEmailAnalysis(
	ctx context.Context,
	rr *dnsx.Resolver,
	domain string,
	res *model.Result,
	selectors []string,
	rec *evidence.Recorder,
	record func(typ, target, source string, data any) bool,
	log Logger,
) *model.EmailAnalysis {
	spfValues := txtValuesFromRecords(res.Records, domain)
	dmarcValues := txtValuesFromRecords(res.Records, "_dmarc."+domain)
	observations := make([]emailauth.SelectorObservation, 0, len(selectors))
	for _, selector := range selectors {
		if ctx.Err() != nil {
			break
		}
		name := selector + "._domainkey." + domain
		obs := emailauth.SelectorObservation{Selector: selector, Name: name}
		rrs, rcode, err := rr.LookupType(ctx, name, "TXT")
		rs := model.RecordSet{Name: name, Type: "TXT", RCode: dnsx.RCodeString(rcode)}
		if err != nil {
			rs.RCode = "ERROR"
			obs.Error = err.Error()
			if ctx.Err() == nil {
				log.Verbose("email DKIM %s: %v", name, err)
			}
		} else {
			rs.RRs = dnsx.CanonicalSet(rrs)
			if len(rs.RRs) > 0 {
				rs.SHA256 = hashLines(rs.RRs)
			}
			obs.TXT = dnsx.TXTValues(rrs)
			obs.CNAME = dnsx.CNAMEs(rrs)
			obs.RCode = rs.RCode
			log.Verbose("email DKIM %s -> %s, %d TXT answer(s)", name, rs.RCode, len(obs.TXT))
		}
		res.Records = append(res.Records, rs)
		data := map[string]any{"qtype": "TXT", "rcode": rs.RCode, "rrs": rs.RRs}
		if rs.SHA256 != "" {
			data["rrs_sha256"] = rs.SHA256
		}
		record("dns_record", name, "dns", data)
		observations = append(observations, obs)
	}
	analysis := emailauth.Analyze(domain, spfValues, dmarcValues, observations)
	if analysis.DKIM.SelectorsChecked == nil {
		// Preserve the requested selector list even if cancellation stopped
		// before the first lookup.
		analysis.DKIM.SelectorsChecked = append([]string(nil), selectors...)
	}
	return analysis
}

func txtValuesFromRecords(records []model.RecordSet, name string) []string {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	var out []string
	for _, rs := range records {
		if rs.Type != "TXT" || strings.ToLower(rs.Name) != name {
			continue
		}
		for _, raw := range rs.RRs {
			rr, err := dns.NewRR(raw)
			if err != nil {
				continue
			}
			if txt, ok := rr.(*dns.TXT); ok {
				out = append(out, strings.Join(txt.Txt, ""))
			}
		}
	}
	return out
}

// emailScoreSummary is the concise terminal line used by the scan logger.
func emailScoreSummary(a *model.EmailAnalysis) string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("%d/%d (%s) · SPF %d/%d · DKIM %d/%d · DMARC %d/%d",
		a.Score, a.MaxScore, a.Grade,
		a.SPF.Score, a.SPF.MaxScore,
		a.DKIM.Score, a.DKIM.MaxScore,
		a.DMARC.Score, a.DMARC.MaxScore,
	)
}

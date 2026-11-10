package emailauth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func testKey() string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("test-dkim-key-", 4)))
}

func TestAnalyzePerfectPosture(t *testing.T) {
	selectors := []SelectorObservation{{
		Selector: "default",
		Name:     "default._domainkey.example.test",
		TXT:      []string{"v=DKIM1; k=rsa; p=" + testKey()},
		RCode:    "NOERROR",
	}}
	got := Analyze("example.test",
		[]string{"v=spf1 include:_spf.example.test -all"},
		[]string{"v=DMARC1; p=reject; rua=mailto:dmarc@example.test; adkim=s; aspf=s"},
		selectors,
	)
	if got.Score != 100 || got.Grade != "A" || got.Verdict != "strong" {
		t.Fatalf("score = %+v", got)
	}
	if !got.SPF.Valid || got.SPF.All != "-all" || got.SPF.DNSLookups != 1 || got.SPF.Score != SPFMaxScore {
		t.Fatalf("spf = %+v", got.SPF)
	}
	if !got.DKIM.Valid || got.DKIM.Score != DKIMmaxScore || len(got.DKIM.ValidSelectors) != 1 || got.DKIM.ValidSelectors[0] != "default" {
		t.Fatalf("dkim = %+v", got.DKIM)
	}
	if !got.DMARC.Valid || got.DMARC.Policy != "reject" || !got.DMARC.Reporting || !got.DMARC.Strict || got.DMARC.Score != DMARCMaxScore {
		t.Fatalf("dmarc = %+v", got.DMARC)
	}
	if len(got.Issues) != 0 {
		t.Fatalf("unexpected issues: %v", got.Issues)
	}
	if !strings.Contains(got.Summary, "Strong") {
		t.Fatalf("summary = %q", got.Summary)
	}
}

func TestAnalyzeMissingEverything(t *testing.T) {
	got := Analyze("example.test", nil, nil, nil)
	if got.Score != 0 || got.Grade != "F" || got.Verdict != "poor" {
		t.Fatalf("score = %+v", got)
	}
	if got.SPF.Present || got.DKIM.Configured || got.DMARC.Present {
		t.Fatalf("presence flags = %+v", got)
	}
	if len(got.Issues) < 3 {
		t.Fatalf("expected SPF, DKIM and DMARC issues, got %v", got.Issues)
	}
}

func TestSPFPermissiveAndLookupLimit(t *testing.T) {
	terms := make([]string, 0, 12)
	for i := 0; i < 11; i++ {
		terms = append(terms, fmt.Sprintf("include:spf%d.example.test", i))
	}
	record := "v=spf1 " + strings.Join(terms, " ") + " +all"
	got := Analyze("example.test", []string{record}, nil, nil)
	if !got.SPF.Valid || got.SPF.Present != true {
		t.Fatalf("spf presence = %+v", got.SPF)
	}
	if got.SPF.DNSLookups != 11 {
		t.Fatalf("dns lookups = %d", got.SPF.DNSLookups)
	}
	if got.SPF.Score != 15 {
		t.Fatalf("spf score = %d, want 15 (base only)", got.SPF.Score)
	}
	if !containsIssue(got.SPF.Issues, "+all") || !containsIssue(got.SPF.Issues, "at most 10") {
		t.Fatalf("issues = %v", got.SPF.Issues)
	}
}

func TestMultipleSPFRecordsFail(t *testing.T) {
	got := Analyze("example.test", []string{
		"v=spf1 -all",
		"v=spf1 include:example.test -all",
	}, nil, nil)
	if !got.SPF.Present || got.SPF.Valid || got.SPF.Score != 0 {
		t.Fatalf("spf = %+v", got.SPF)
	}
	if !containsIssue(got.SPF.Issues, "Multiple SPF") {
		t.Fatalf("issues = %v", got.SPF.Issues)
	}
}

func TestDKIMCNAMEOnly(t *testing.T) {
	got := Analyze("example.test", nil, nil, []SelectorObservation{{
		Selector: "google",
		Name:     "google._domainkey.example.test",
		CNAME:    []string{"google.dkim.example.net"},
		RCode:    "NOERROR",
	}})
	if !got.DKIM.Configured || got.DKIM.Valid || got.DKIM.Score != 15 {
		t.Fatalf("dkim = %+v", got.DKIM)
	}
	if len(got.DKIM.FoundSelectors) != 1 || got.DKIM.FoundSelectors[0] != "google" {
		t.Fatalf("found = %v", got.DKIM.FoundSelectors)
	}
}

func TestDKIMRevokedAndInvalid(t *testing.T) {
	got := Analyze("example.test", nil, nil, []SelectorObservation{
		{Selector: "default", TXT: []string{"v=DKIM1; k=rsa; p="}},
		{Selector: "google", TXT: []string{"v=DKIM1; p=not-base64!!!"}},
	})
	if got.DKIM.Valid || got.DKIM.Score != 0 {
		t.Fatalf("dkim = %+v", got.DKIM)
	}
	statuses := map[string]string{}
	for _, s := range got.DKIM.Selectors {
		statuses[s.Selector] = s.Status
	}
	if statuses["default"] != "revoked" || statuses["google"] != "invalid" {
		t.Fatalf("statuses = %v", statuses)
	}
}

func TestDMARCNoneAndInvalid(t *testing.T) {
	got := Analyze("example.test", nil,
		[]string{"v=DMARC1; p=none; rua=mailto:dmarc@example.test; adkim=s"}, nil)
	if !got.DMARC.Valid || got.DMARC.Policy != "none" || got.DMARC.Score != 28 {
		t.Fatalf("dmarc = %+v", got.DMARC)
	}
	if !containsIssue(got.DMARC.Issues, "monitor-only") {
		t.Fatalf("issues = %v", got.DMARC.Issues)
	}

	multiple := Analyze("example.test", nil, []string{
		"v=DMARC1; p=reject",
		"v=DMARC1; p=none",
	}, nil)
	if !multiple.DMARC.Present || multiple.DMARC.Valid || multiple.DMARC.Score != 0 {
		t.Fatalf("multiple dmarc = %+v", multiple.DMARC)
	}

	malformed := Analyze("example.test", nil,
		[]string{"p=reject; rua=mailto:dmarc@example.test"}, nil)
	if malformed.DMARC.Valid || !containsIssue(malformed.DMARC.Issues, "must begin") {
		t.Fatalf("malformed dmarc = %+v", malformed.DMARC)
	}
}

func TestSelectorValidation(t *testing.T) {
	got, err := CleanSelectors(nil)
	if err != nil || len(got) != len(DefaultSelectors) {
		t.Fatalf("defaults = %v, %v", got, err)
	}
	got, err = CleanSelectors([]string{"Google", "selector1,selector2", "GOOGLE"})
	if err != nil || strings.Join(got, ",") != "google,selector1,selector2" {
		t.Fatalf("clean = %v, %v", got, err)
	}
	if _, err := CleanSelectors([]string{"bad selector"}); err == nil {
		t.Fatal("expected invalid selector error")
	}
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("s%d", i)
	}
	if _, err := CleanSelectors(tooMany); err == nil {
		t.Fatal("expected selector-limit error")
	}
}

func containsIssue(issues []string, needle string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, needle) {
			return true
		}
	}
	return false
}

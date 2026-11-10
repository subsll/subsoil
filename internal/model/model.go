// Package model contains the scan result types shared by the scanner,
// the evidence recorder and the report writers.
package model

import "time"

const ToolName = "subsoil"

// Version is overridden at build time with -ldflags "-X github.com/subsll/subsoil/internal/model.Version=..."
var Version = "dev"

// ScanOptions is the serialisable subset of the runtime configuration that is
// recorded in the report so a run can be explained after the fact.
type ScanOptions struct {
	Passive       bool     `json:"passive"`
	Brute         bool     `json:"brute"`
	Extended      bool     `json:"extended"`
	Words         int      `json:"words"`
	Wordlist      string   `json:"wordlist,omitempty"`
	AXFR          bool     `json:"axfr"`
	HTTP          bool     `json:"http"`
	SRV           bool     `json:"srv"`
	PTR           bool     `json:"ptr"`
	Recursive     bool     `json:"recursive"`
	IPv6          bool     `json:"ipv6"`
	ResolveIPs    bool     `json:"resolve_ips"`
	Workers       int      `json:"workers"`
	QPS           int      `json:"qps"`
	TimeoutSecond int      `json:"timeout_seconds"`
	Sources       []string `json:"sources,omitempty"`
	MaxHosts      int      `json:"max_hosts"`
	Capture       bool     `json:"capture"`
	EmailAnalysis bool     `json:"email_analysis"`
	DKIMSelectors []string `json:"dkim_selectors,omitempty"`
}

// RecordSet is one DNS query result, with a hash over the canonical RRset.
type RecordSet struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	RCode  string   `json:"rcode"`
	RRs    []string `json:"rrs,omitempty"`
	SHA256 string   `json:"sha256,omitempty"`
}

// EmailAnalysis is the opt-in SPF/DKIM/DMARC posture score. It measures DNS
// configuration hygiene, not deliverability or whether a message is authentic.
type EmailAnalysis struct {
	Score    int        `json:"score"`
	MaxScore int        `json:"max_score"`
	Grade    string     `json:"grade"`
	Verdict  string     `json:"verdict"`
	Summary  string     `json:"summary,omitempty"`
	SPF      EmailSPF   `json:"spf"`
	DKIM     EmailDKIM  `json:"dkim"`
	DMARC    EmailDMARC `json:"dmarc"`
	Issues   []string   `json:"issues,omitempty"`
	SHA256   string     `json:"sha256,omitempty"`
}

// EmailSPF summarises an SPF record and its policy.
type EmailSPF struct {
	Present    bool     `json:"present"`
	Valid      bool     `json:"valid"`
	Score      int      `json:"score"`
	MaxScore   int      `json:"max_score"`
	Record     string   `json:"record,omitempty"`
	Records    int      `json:"records,omitempty"`
	All        string   `json:"all,omitempty"`
	DNSLookups int      `json:"dns_lookups"`
	Issues     []string `json:"issues,omitempty"`
}

// EmailDKIM summarises the DKIM selectors that were checked.
type EmailDKIM struct {
	Configured       bool           `json:"configured"`
	Valid            bool           `json:"valid"`
	Score            int            `json:"score"`
	MaxScore         int            `json:"max_score"`
	SelectorsChecked []string       `json:"selectors_checked,omitempty"`
	Selectors        []DKIMSelector `json:"selectors,omitempty"`
	FoundSelectors   []string       `json:"found_selectors,omitempty"`
	ValidSelectors   []string       `json:"valid_selectors,omitempty"`
	Issues           []string       `json:"issues,omitempty"`
}

// DKIMSelector is one selector look-up.
type DKIMSelector struct {
	Selector string `json:"selector"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Valid    bool   `json:"valid"`
	KeyType  string `json:"key_type,omitempty"`
	CNAME    string `json:"cname,omitempty"`
	Record   string `json:"record,omitempty"`
	Issue    string `json:"issue,omitempty"`
}

// EmailDMARC summarises the DMARC record and policy.
type EmailDMARC struct {
	Present         bool     `json:"present"`
	Valid           bool     `json:"valid"`
	Score           int      `json:"score"`
	MaxScore        int      `json:"max_score"`
	Record          string   `json:"record,omitempty"`
	Records         int      `json:"records,omitempty"`
	Policy          string   `json:"policy,omitempty"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	Percent         int      `json:"percent,omitempty"`
	Reporting       bool     `json:"reporting"`
	Strict          bool     `json:"strict"`
	Issues          []string `json:"issues,omitempty"`
}

// Host is a discovered name. Hash is the SHA-256 of the evidence record that
// first proved the name exists.
type Host struct {
	Name      string    `json:"name"`
	IPs       []string  `json:"ips,omitempty"`
	AAAA      []string  `json:"aaaa,omitempty"`
	IPsHidden bool      `json:"ips_hidden,omitempty"`
	CNAME     string    `json:"cname,omitempty"`
	Sources   []string  `json:"sources,omitempty"`
	Wildcard  bool      `json:"wildcard,omitempty"`
	Resolved  bool      `json:"resolved"`
	RCode     string    `json:"rcode,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	Hash      string    `json:"sha256"`
}

// SRV is a service record finding.
type SRV struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	SHA256   string `json:"sha256,omitempty"`
}

// PTR is a reverse lookup finding.
type PTR struct {
	IP     string   `json:"ip"`
	Names  []string `json:"names,omitempty"`
	SHA256 string   `json:"sha256,omitempty"`
}

// AXFR is a zone-transfer attempt against one authoritative server.
type AXFR struct {
	NS            string   `json:"ns"`
	Address       string   `json:"address,omitempty"`
	OK            bool     `json:"ok"`
	Records       []string `json:"records,omitempty"`
	RecordsSHA256 string   `json:"records_sha256,omitempty"`
	SHA256        string   `json:"sha256,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// TLS captures the leaf certificate of a probed HTTPS service.
type TLS struct {
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	DNSNames  []string  `json:"dns_names,omitempty"`
}

// HTTP is a single web probe result. BodySHA256 is proof of the response body
// observed at Time; it is not a hash of the whole page if BodyLen == BodyLimit.
type HTTP struct {
	Host        string    `json:"host"`
	URL         string    `json:"url"`
	Scheme      string    `json:"scheme"`
	Status      int       `json:"status"`
	Server      string    `json:"server,omitempty"`
	Title       string    `json:"title,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Redirects   []string  `json:"redirects,omitempty"`
	TLS         *TLS      `json:"tls,omitempty"`
	BodySHA256  string    `json:"body_sha256,omitempty"`
	BodyLen     int64     `json:"body_len,omitempty"`
	BodyFile    string    `json:"body_file,omitempty"`
	Time        time.Time `json:"time"`
	Error       string    `json:"error,omitempty"`
	SHA256      string    `json:"sha256"`
}

// Wildcard describes the wildcard-DNS fingerprint used to filter brute force
// false positives.
type Wildcard struct {
	Enabled    bool     `json:"enabled"`
	Probes     []string `json:"probes,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	CNAMEs     []string `json:"cnames,omitempty"`
	Filtered   int      `json:"filtered"`
	DetectedAt string   `json:"detected_at,omitempty"`
}

// Stats is run telemetry.
type Stats struct {
	DNSQueries    int64 `json:"dns_queries"`
	PassiveNames  int   `json:"passive_names"`
	BruteTried    int   `json:"brute_tried"`
	BruteHits     int   `json:"brute_hits"`
	WildcardDrops int   `json:"wildcard_dropped"`
	HTTPProbes    int   `json:"http_probes"`
	ZoneTransfers int   `json:"zone_transfers"`
	NamesResolved int   `json:"names_resolved"`
}

// EvidenceInfo summarises the tamper-evident log written for the run.
type EvidenceInfo struct {
	File       string `json:"file"`
	Records    int    `json:"records"`
	RootSHA256 string `json:"root_sha256"`
	FileSHA256 string `json:"file_sha256"`
	ChainOK    bool   `json:"chain_ok"`
}

// Result is the complete output of one scan.
type Result struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	Domain        string         `json:"domain"`
	Started       time.Time      `json:"started"`
	Finished      time.Time      `json:"finished"`
	DurationMS    int64          `json:"duration_ms"`
	Resolvers     []string       `json:"resolvers"`
	Options       ScanOptions    `json:"options"`
	Records       []RecordSet    `json:"records,omitempty"`
	Hosts         []Host         `json:"hosts,omitempty"`
	SRV           []SRV          `json:"srv,omitempty"`
	PTR           []PTR          `json:"ptr,omitempty"`
	AXFR          []AXFR         `json:"axfr,omitempty"`
	HTTP          []HTTP         `json:"http,omitempty"`
	EmailAnalysis *EmailAnalysis `json:"email_analysis,omitempty"`
	Wildcard      Wildcard       `json:"wildcard"`
	Stats         Stats          `json:"stats"`
	Errors        []string       `json:"errors,omitempty"`
	Evidence      EvidenceInfo   `json:"evidence"`
}

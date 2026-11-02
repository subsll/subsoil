// Package scan orchestrates a reconnaissance run and records every finding in
// the hash-chained evidence log.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"subsoil/internal/brute"
	"subsoil/internal/dnsx"
	"subsoil/internal/evidence"
	"subsoil/internal/model"
	"subsoil/internal/passive"
	"subsoil/internal/probe"
	"subsoil/internal/wordlist"

	"github.com/miekg/dns"
)

// Logger is the progress sink used by a scan. logx.Logger implements it.
type Logger interface {
	Info(format string, args ...any)
	Verbose(format string, args ...any)
	Success(format string, args ...any)
	Warn(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)    {}
func (nopLogger) Verbose(string, ...any) {}
func (nopLogger) Success(string, ...any) {}
func (nopLogger) Warn(string, ...any)    {}

// Options configures a scan.
type Options struct {
	Domain        string
	OutDir        string
	PassiveOnly   bool
	Brute         bool
	Extended      bool
	WordlistPaths []string
	AXFR          bool
	HTTP          bool
	SRV           bool
	PTR           bool
	Recursive     bool
	IPv6          bool
	NoIPLookup    bool
	Capture       bool
	Workers       int
	QPS           int
	Timeout       time.Duration
	Resolvers     []string
	Sources       []string
	SourceTimeout time.Duration
	OTXKey        string
	MaxHosts      int
	MaxHTTP       int
	Exclude       *regexp.Regexp
	Log           Logger
	Stage         func(string)
}

func (o *Options) stage(name string) {
	if o.Stage != nil {
		o.Stage(name)
	}
}

type agg struct {
	name     string
	ips      map[string]struct{}
	aaaa     map[string]struct{}
	cname    string
	sources  map[string]struct{}
	first    time.Time
	resolved bool
	rcode    string
}

func newAgg(name string) *agg {
	return &agg{
		name:    name,
		ips:     make(map[string]struct{}),
		aaaa:    make(map[string]struct{}),
		sources: make(map[string]struct{}),
		first:   time.Now().UTC(),
	}
}

func (a *agg) addSource(s string) {
	if s != "" {
		a.sources[s] = struct{}{}
	}
}

func (a *agg) ipList() []string   { return sortedSet(a.ips) }
func (a *agg) aaaaList() []string { return sortedSet(a.aaaa) }
func (a *agg) srcList() []string  { return sortedSet(a.sources) }

type resolvedName struct {
	name  string
	ips   []string
	aaaa  []string
	cname string
	rcode string
	err   error
}

// axfrPort is a variable so tests can point zone transfers at a local server.
var axfrPort = "53"

// Run executes the scan. A partial result is returned when ctx is cancelled.
func Run(ctx context.Context, opt Options) (res *model.Result, err error) {
	started := time.Now().UTC()
	if opt.Log == nil {
		opt.Log = nopLogger{}
	}
	if opt.Workers <= 0 {
		opt.Workers = 20
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.SourceTimeout <= 0 {
		opt.SourceTimeout = 30 * time.Second
	}
	if opt.MaxHosts <= 0 {
		opt.MaxHosts = 5000
	}
	if opt.MaxHTTP <= 0 {
		opt.MaxHTTP = 200
	}

	domain, err := dnsx.ParseName(opt.Domain)
	if err != nil {
		return nil, err
	}
	if opt.PassiveOnly && len(opt.Sources) == 0 {
		return nil, fmt.Errorf("passive mode needs at least one --sources entry")
	}
	if err := os.MkdirAll(opt.OutDir, 0o755); err != nil {
		return nil, err
	}

	rec, err := evidence.NewRecorder(filepath.Join(opt.OutDir, "evidence.jsonl"))
	if err != nil {
		return nil, err
	}

	res = &model.Result{
		Tool:      model.ToolName,
		Version:   model.Version,
		Domain:    domain,
		Started:   started,
		Resolvers: append([]string(nil), opt.Resolvers...),
		Options: model.ScanOptions{
			Passive:       opt.PassiveOnly,
			Brute:         opt.Brute && !opt.PassiveOnly,
			Extended:      opt.Extended,
			Wordlist:      strings.Join(opt.WordlistPaths, ", "),
			AXFR:          opt.AXFR && !opt.PassiveOnly,
			HTTP:          opt.HTTP && !opt.PassiveOnly,
			SRV:           opt.SRV && !opt.PassiveOnly,
			PTR:           opt.PTR && !opt.PassiveOnly && !opt.NoIPLookup,
			Recursive:     opt.Recursive && !opt.PassiveOnly,
			IPv6:          opt.IPv6,
			ResolveIPs:    !opt.NoIPLookup,
			Workers:       opt.Workers,
			QPS:           opt.QPS,
			TimeoutSecond: int(opt.Timeout / time.Second),
			Sources:       append([]string(nil), opt.Sources...),
			MaxHosts:      opt.MaxHosts,
			Capture:       opt.Capture,
		},
	}
	defer func() {
		info, cerr := rec.Close()
		if cerr != nil && err == nil {
			err = cerr
		}
		res.Evidence = model.EvidenceInfo{
			File:       info.File,
			Records:    info.Records,
			RootSHA256: info.RootSHA256,
			FileSHA256: info.FileSHA256,
			ChainOK:    info.ChainOK,
		}
		res.Finished = time.Now().UTC()
		res.DurationMS = res.Finished.Sub(res.Started).Milliseconds()
	}()

	opt.Log.Verbose("evidence log: %s", rec.Path())
	if opt.NoIPLookup {
		opt.Log.Info("IP lookup disabled for discovered names; addresses will be hidden")
	}
	if _, aerr := rec.Add("scan_start", domain, "subsoil", map[string]any{
		"version":      model.Version,
		"resolvers":    opt.Resolvers,
		"passive_only": opt.PassiveOnly,
		"brute":        opt.Brute && !opt.PassiveOnly,
		"resolve_ips":  !opt.NoIPLookup,
		"sources":      opt.Sources,
		"started":      started.Format(time.RFC3339Nano),
	}); aerr != nil {
		return res, aerr
	}

	excluded := func(name string) bool {
		return opt.Exclude != nil && opt.Exclude.MatchString(name)
	}
	var errMu sync.Mutex
	addErr := func(format string, args ...any) {
		errMu.Lock()
		defer errMu.Unlock()
		if len(res.Errors) < 50 {
			res.Errors = append(res.Errors, fmt.Sprintf(format, args...))
		}
	}
	record := func(typ, target, source string, data any) bool {
		if _, aerr := rec.Add(typ, target, source, data); aerr != nil {
			addErr("evidence write failed: %v", aerr)
			return false
		}
		return true
	}

	opt.stage("preparing")

	// Load the dictionary before any network work so a bad path fails fast
	// and the wordlist is visible in the startup log.
	var words []string
	if opt.Brute && !opt.PassiveOnly {
		opt.stage("loading wordlist")
		if len(opt.WordlistPaths) > 0 {
			var wl wordlist.Result
			wl, err = wordlist.LoadPaths(opt.WordlistPaths)
			if err != nil {
				return res, err
			}
			words = wl.Words
			opt.Log.Info("wordlist: %d label(s) from %d source(s)", len(words), len(wl.Sources))
			for _, src := range wl.Sources {
				opt.Log.Verbose("wordlist source: %s", src)
			}
			if opt.Extended {
				opt.Log.Verbose("custom wordlist overrides --extended")
			}
		} else {
			words, err = wordlist.Load(opt.Extended)
			if err != nil {
				return res, err
			}
			opt.Log.Verbose("wordlist: embedded list (%d labels)", len(words))
		}
		if len(words) > opt.MaxHosts*4 {
			opt.Log.Warn("wordlist truncated from %d to %d labels (--max-hosts)", len(words), opt.MaxHosts*4)
			words = words[:opt.MaxHosts*4]
		}
		res.Options.Words = len(words)
	}

	hosts := make(map[string]*agg)
	addHost := func(name string, ips, aaaa []string, cname, source string, resolved bool) {
		a, ok := hosts[name]
		if !ok {
			a = newAgg(name)
			hosts[name] = a
		}
		for _, ip := range ips {
			if isV6(ip) {
				a.aaaa[ip] = struct{}{}
			} else {
				a.ips[ip] = struct{}{}
			}
		}
		for _, ip := range aaaa {
			a.aaaa[ip] = struct{}{}
		}
		if cname != "" {
			a.cname = cname
		}
		a.addSource(source)
		a.resolved = a.resolved || resolved
	}

	// Start passive collection early: it is the slowest network step.
	var (
		passCh    chan passResult
		passNames []string
	)
	if len(opt.Sources) > 0 {
		opt.stage("passive sources")
		passCh = make(chan passResult, 1)
		go func() {
			names, errs := passive.Resolve(ctx, domain, opt.Sources, passive.Options{
				Timeout:    opt.SourceTimeout,
				OTXKey:     opt.OTXKey,
				VerboseLog: func(format string, args ...any) { opt.Log.Verbose(format, args...) },
			})
			passCh <- passResult{names: names, errs: errs}
		}()
		opt.Log.Info("passive sources: %s", strings.Join(opt.Sources, ", "))
	}

	// Baseline DNS records. In passive-only mode no packet is sent to any DNS
	// server, including public resolvers.
	var (
		nsNames []string
		rr      *dnsx.Resolver
	)
	if !opt.PassiveOnly {
		opt.stage("baseline DNS")
		rr, err = dnsx.New(opt.Resolvers, opt.Timeout, opt.QPS)
		if err != nil {
			return res, err
		}
		rr.SetVerboseLog(func(format string, args ...any) { opt.Log.Verbose(format, args...) })
		mtu := []struct{ name, typ string }{
			{domain, "A"}, {domain, "AAAA"}, {domain, "NS"}, {domain, "MX"},
			{domain, "TXT"}, {domain, "SOA"}, {domain, "CAA"},
			{"_dmarc." + domain, "TXT"},
		}
		for _, q := range mtu {
			if ctx.Err() != nil {
				break
			}
			rrs, rcode, qerr := rr.LookupType(ctx, q.name, q.typ)
			rs := model.RecordSet{Name: q.name, Type: q.typ, RCode: dnsx.RCodeString(rcode)}
			if qerr != nil {
				rs.RCode = "ERROR"
				addErr("%s %s: %v", q.typ, q.name, qerr)
			} else {
				rs.RRs = dnsx.CanonicalSet(rrs)
				if len(rs.RRs) > 0 {
					rs.SHA256 = hashLines(rs.RRs)
				}
				if q.typ == "NS" {
					nsNames = dnsx.Names(rrs)
				}
			}
			res.Records = append(res.Records, rs)
			data := map[string]any{"qtype": q.typ, "rcode": rs.RCode, "rrs": rs.RRs}
			if rs.SHA256 != "" {
				data["rrs_sha256"] = rs.SHA256
			}
			record("dns_record", q.name, "dns", data)
		}
	}

	if !opt.PassiveOnly {
		opt.Log.Verbose("collected %d DNS record set(s)", len(res.Records))
	}

	// Wildcard fingerprint, needed before brute forcing.
	var wildcard model.Wildcard
	if !opt.PassiveOnly {
		opt.stage("wildcard detection")
		w, werr := dnsx.DetectWildcard(ctx, rr, domain, 3)
		if werr != nil {
			addErr("wildcard detection: %v", werr)
		}
		wildcard = w
		res.Wildcard = w
		res.Wildcard.DetectedAt = time.Now().UTC().Format(time.RFC3339)
		if w.Enabled {
			opt.Log.Warn("wildcard DNS detected (%d address(es)); brute results will be filtered — large wordlists may be mostly wasted", len(w.IPs))
		}
		record("wildcard", domain, "dns", map[string]any{
			"enabled": w.Enabled, "probes": w.Probes, "ips": w.IPs, "cnames": w.CNAMEs,
		})
	}

	// Collect passive names.
	if passCh != nil {
		opt.stage("passive sources")
		pr := <-passCh
		for _, src := range opt.Sources {
			if _, failed := pr.errs[src]; failed {
				continue
			}
			names := pr.names[src]
			opt.Log.Info("%s: %d name(s)", src, len(names))
			for _, name := range names {
				if excluded(name) || len(passNames) >= 100000 {
					continue
				}
				passNames = append(passNames, name)
				res.Stats.PassiveNames++
				addHost(name, nil, nil, "", src, false)
				record("subdomain", name, "passive:"+src, map[string]any{"source": src})
			}
		}
		for src, serr := range pr.errs {
			msg := strings.TrimPrefix(serr.Error(), src+": ")
			opt.Log.Warn("passive %s: %s", src, msg)
			addErr("passive %s: %s", src, msg)
			record("source_error", domain, "passive:"+src, map[string]any{"error": msg})
		}
		passNames = dedupeSorted(passNames)
		opt.Log.Verbose("passive names: %d unique", len(passNames))
		if len(passNames) > opt.MaxHosts {
			opt.Log.Warn("%d passive names, resolving the first %d (--max-hosts)", len(passNames), opt.MaxHosts)
			passNames = passNames[:opt.MaxHosts]
		}
	}

	// Start brute force and passive-name resolution concurrently.
	var (
		bruteCh   chan brute.Result
		resolveCh chan []resolvedName
		axfrCh    chan []model.AXFR
	)
	if opt.Brute && !opt.PassiveOnly {
		opt.stage("brute force")
		bruteCh = make(chan brute.Result, 1)
		bruteStart := time.Now()
		var progressMu sync.Mutex
		var lastProgress time.Time
		est := ""
		if opt.QPS > 0 {
			d := time.Duration(float64(len(words)) / float64(opt.QPS) * float64(time.Second))
			est = fmt.Sprintf(" (~%s at %d qps)", d.Round(time.Second), opt.QPS)
		}
		go func() {
			bruteCh <- brute.Run(ctx, rr, domain, words, brute.Options{
				Workers:  opt.Workers,
				IPv6:     opt.IPv6 && !opt.NoIPLookup,
				Wildcard: wildcard,
				Progress: func(done, total, hits int) {
					now := time.Now()
					progressMu.Lock()
					if done < total && now.Sub(lastProgress) < 2*time.Second {
						progressMu.Unlock()
						return
					}
					lastProgress = now
					progressMu.Unlock()

					pct := 0
					if total > 0 {
						pct = done * 100 / total
					}
					elapsed := now.Sub(bruteStart)
					eta := ""
					if done > 0 && elapsed > 0 {
						rate := float64(done) / elapsed.Seconds()
						if rate > 0 {
							left := time.Duration(float64(total-done) / rate * float64(time.Second))
							eta = " · " + left.Round(100*time.Millisecond).String() + " left"
						}
					}
					opt.Log.Info("brute: %d/%d (%d%%) · %d hit(s) · %s elapsed%s",
						done, total, pct, hits, elapsed.Round(100*time.Millisecond), eta)
				},
			})
		}()
		opt.Log.Info("brute force: %d words, %d workers, %d qps%s", len(words), opt.Workers, opt.QPS, est)
		if opt.QPS > 0 && opt.QPS < 250 && len(words)/opt.QPS > 120 {
			opt.Log.Info("hint: --fast raises the rate to 250 qps (noisier)")
		}
	}

	if !opt.PassiveOnly && !opt.NoIPLookup && len(passNames) > 0 {
		opt.stage("resolving passive names")
		names := append([]string(nil), passNames...)
		resolveCh = make(chan []resolvedName, 1)
		go func() {
			resolveCh <- resolveNames(ctx, rr, names, opt.Workers, opt.IPv6, rec, addErr)
		}()
	}

	if opt.AXFR && !opt.PassiveOnly && len(nsNames) > 0 {
		opt.stage("zone transfers")
		opt.Log.Info("zone transfer: %d nameserver(s) to test", len(nsNames))
		axfrCh = make(chan []model.AXFR, 1)
		go func() {
			axfrCh <- attemptAXFR(ctx, rr, domain, nsNames, opt.Timeout, rec, addErr, opt.Log)
		}()
	}

	if resolveCh != nil {
		opt.stage("resolving passive names")
		for _, rn := range <-resolveCh {
			if rn.err != nil {
				if ctx.Err() == nil {
					addErr("resolve %s: %v", rn.name, rn.err)
				}
				continue
			}
			if len(rn.ips) == 0 && len(rn.aaaa) == 0 && rn.cname == "" {
				addHost(rn.name, nil, nil, "", "", false)
				if a := hosts[rn.name]; a != nil {
					a.rcode = rn.rcode
				}
				continue
			}
			res.Stats.NamesResolved++
			addHost(rn.name, rn.ips, rn.aaaa, rn.cname, "", true)
		}
	}

	if bruteCh != nil {
		opt.stage("brute force")
		br := <-bruteCh
		res.Wildcard.Filtered = br.WildcardDrops
		res.Stats.BruteTried = br.Tried
		res.Stats.BruteHits = br.Hits
		res.Stats.WildcardDrops += br.WildcardDrops
		if br.Errors > 0 {
			addErr("brute force: %d query error(s)", br.Errors)
		}
		for _, h := range br.Hosts {
			if opt.NoIPLookup {
				opt.Log.Verbose("brute hit: %s (IPs hidden)", h.Name)
			} else {
				opt.Log.Verbose("brute hit: %s (%s)", h.Name, strings.Join(append(append([]string{}, h.IPs...), h.AAAA...), ", "))
			}
			addHost(h.Name, h.IPs, h.AAAA, h.CNAME, "brute", true)
			data := map[string]any{"ips": h.IPs, "aaaa": h.AAAA, "cname": h.CNAME}
			if opt.NoIPLookup {
				data = map[string]any{"ips_hidden": true, "cname": h.CNAME}
			}
			record("subdomain", h.Name, "brute", data)
		}
		opt.Log.Success("brute force: %d hit(s), %d wildcard-filtered, %d query error(s)", br.Hits, br.WildcardDrops, br.Errors)
	}

	if axfrCh != nil {
		opt.stage("zone transfers")
		res.AXFR = <-axfrCh
		res.Stats.ZoneTransfers = len(res.AXFR)
		ok := 0
		for _, z := range res.AXFR {
			if z.OK {
				ok++
				opt.Log.Success("AXFR succeeded for %s via %s (%d records)", domain, z.NS, len(z.Records))
			}
		}
		if ok == 0 {
			opt.Log.Info("zone transfer: no server allowed AXFR")
		}
	}

	// Recursive one-level discovery under interesting parents.
	if opt.Recursive && !opt.PassiveOnly && ctx.Err() == nil && len(words) > 0 {
		sub := words
		if len(sub) > 150 {
			sub = sub[:150]
		}
		var parents []string
		for name, a := range hosts {
			if a.resolved && (len(a.ips)+len(a.aaaa)) > 0 && name != domain {
				parents = append(parents, name)
			}
		}
		sort.Strings(parents)
		if len(parents) > 15 {
			parents = parents[:15]
		}
		for _, parent := range parents {
			if ctx.Err() != nil {
				break
			}
			opt.stage("recursive scan " + parent)
			pw, _ := dnsx.DetectWildcard(ctx, rr, parent, 2)
			rres := brute.Run(ctx, rr, parent, sub, brute.Options{Workers: 8, IPv6: opt.IPv6, Wildcard: pw})
			res.Stats.WildcardDrops += rres.WildcardDrops
			if len(rres.Hosts) > 0 {
				opt.Log.Info("recursive %s: %d host(s)", parent, len(rres.Hosts))
			}
			for _, h := range rres.Hosts {
				addHost(h.Name, h.IPs, h.AAAA, h.CNAME, "recursive", true)
				record("subdomain", h.Name, "recursive", map[string]any{"parent": parent, "ips": h.IPs})
			}
		}
	}

	// SRV records.
	if opt.SRV && !opt.PassiveOnly && ctx.Err() == nil {
		opt.stage("SRV records")
		for _, svc := range srvServices {
			rrs, rcode, qerr := rr.LookupType(ctx, svc+"."+domain, "SRV")
			if qerr != nil || rcode != dns.RcodeSuccess || len(rrs) == 0 {
				continue
			}
			for _, raw := range rrs {
				s, ok := raw.(*dns.SRV)
				if !ok {
					continue
				}
				entry := model.SRV{
					Name:     svc + "." + domain,
					Target:   strings.TrimSuffix(s.Target, "."),
					Port:     s.Port,
					Priority: s.Priority,
					Weight:   s.Weight,
				}
				ev, aerr := rec.Add("srv", entry.Name, "dns", map[string]any{
					"target": entry.Target, "port": entry.Port, "priority": entry.Priority, "weight": entry.Weight,
				})
				if aerr != nil {
					addErr("evidence write failed: %v", aerr)
				} else {
					entry.SHA256 = ev.Hash
				}
				res.SRV = append(res.SRV, entry)
			}
		}
	}

	// Reverse DNS for discovered addresses.
	if opt.PTR && opt.NoIPLookup && !opt.PassiveOnly {
		opt.Log.Warn("--ptr skipped because --no-resolve-ips is set")
	}
	if opt.PTR && !opt.PassiveOnly && !opt.NoIPLookup && ctx.Err() == nil {
		opt.stage("reverse DNS")
		ips := make([]string, 0, 64)
		for _, a := range hosts {
			ips = append(ips, a.ipList()...)
			ips = append(ips, a.aaaaList()...)
		}
		ips = dedupeSorted(ips)
		if len(ips) > 256 {
			ips = ips[:256]
		}
		for _, ip := range ips {
			if ctx.Err() != nil {
				break
			}
			rev, rerr := dns.ReverseAddr(ip)
			if rerr != nil {
				continue
			}
			rrs, _, qerr := rr.LookupType(ctx, rev, "PTR")
			if qerr != nil || len(rrs) == 0 {
				continue
			}
			names := dnsx.Names(rrs)
			if len(names) == 0 {
				continue
			}
			entry := model.PTR{IP: ip, Names: names}
			ev, aerr := rec.Add("ptr", ip, "dns", map[string]any{"names": names})
			if aerr != nil {
				addErr("evidence write failed: %v", aerr)
			} else {
				entry.SHA256 = ev.Hash
			}
			res.PTR = append(res.PTR, entry)
		}
		sort.Slice(res.PTR, func(i, j int) bool { return res.PTR[i].IP < res.PTR[j].IP })
	}

	// Web probes.
	if opt.HTTP && !opt.PassiveOnly && ctx.Err() == nil {
		opt.stage("HTTP probes")
		var targets []string
		for name, a := range hosts {
			if a.resolved && (len(a.ips)+len(a.aaaa)) > 0 {
				targets = append(targets, name)
			}
		}
		sort.Strings(targets)
		if len(targets) > opt.MaxHTTP {
			targets = targets[:opt.MaxHTTP]
		}
		probed := probeAll(ctx, targets, probe.Options{
			Timeout:    opt.Timeout,
			Insecure:   true,
			Capture:    opt.Capture,
			BodyDir:    filepath.Join(opt.OutDir, "bodies"),
			MaxBody:    2 << 20,
			VerboseLog: func(format string, args ...any) { opt.Log.Verbose(format, args...) },
		}, 8, func(h model.HTTP) {
			data := map[string]any{
				"status": h.Status, "url": h.URL, "scheme": h.Scheme,
				"server": h.Server, "title": h.Title, "content_type": h.ContentType,
				"redirects": h.Redirects, "body_sha256": h.BodySHA256, "body_len": h.BodyLen,
			}
			if h.TLS != nil {
				data["tls"] = map[string]any{
					"subject": h.TLS.Subject, "issuer": h.TLS.Issuer,
					"not_after": h.TLS.NotAfter.Format(time.RFC3339), "dns_names": h.TLS.DNSNames,
				}
			}
			if h.Error != "" {
				data["error"] = h.Error
			}
			if h.BodyFile != "" {
				data["body_file"] = h.BodyFile
			}
			ev, aerr := rec.Add("http", h.Host, "http", data)
			if aerr != nil {
				addErr("evidence write failed: %v", aerr)
			}
			h.SHA256 = ev.Hash
			res.HTTP = append(res.HTTP, h)
		})
		res.Stats.HTTPProbes = probed
		sort.Slice(res.HTTP, func(i, j int) bool { return res.HTTP[i].Host < res.HTTP[j].Host })
	}

	// Emit the canonical host record: this hash is the per-finding proof.
	opt.stage("collecting findings")
	names := make([]string, 0, len(hosts))
	for name := range hosts {
		if !excluded(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		a := hosts[name]
		if a.resolved && a.rcode == "" {
			a.rcode = "NOERROR"
		}
		h := model.Host{
			Name:      name,
			IPs:       a.ipList(),
			AAAA:      a.aaaaList(),
			CNAME:     a.cname,
			Sources:   a.srcList(),
			Resolved:  a.resolved,
			RCode:     a.rcode,
			FirstSeen: a.first,
		}
		hostData := map[string]any{
			"ips": h.IPs, "aaaa": h.AAAA, "cname": h.CNAME,
			"sources": h.Sources, "resolved": h.Resolved, "rcode": h.RCode,
		}
		if opt.NoIPLookup {
			h.IPs, h.AAAA = nil, nil
			h.IPsHidden = true
			hostData["ips"], hostData["aaaa"] = []string{}, []string{}
			hostData["ips_hidden"] = true
		}
		ev, aerr := rec.Add("host", name, "subsoil", hostData)
		if aerr != nil {
			addErr("evidence write failed: %v", aerr)
		}
		h.Hash = ev.Hash
		res.Hosts = append(res.Hosts, h)
	}
	if rr != nil {
		res.Stats.DNSQueries = rr.Queries()
	}

	opt.Log.Verbose("scan complete: %d host(s), %d DNS quer(ies), %d error(s)",
		len(res.Hosts), res.Stats.DNSQueries, len(res.Errors))

	if ctx.Err() != nil {
		addErr("scan interrupted: %v", ctx.Err())
	}

	opt.stage("finalizing evidence")
	stats := map[string]any{
		"dns_queries": res.Stats.DNSQueries, "passive_names": res.Stats.PassiveNames,
		"brute_tried": res.Stats.BruteTried, "brute_hits": res.Stats.BruteHits,
		"hosts": len(res.Hosts), "http_probes": res.Stats.HTTPProbes,
		"duration_ms": time.Since(started).Milliseconds(), "error_count": len(res.Errors),
	}
	if _, aerr := rec.Add("scan_end", domain, "subsoil", stats); aerr != nil {
		addErr("evidence write failed: %v", aerr)
	}
	return res, nil
}

type passResult struct {
	names map[string][]string
	errs  map[string]error
}

func resolveNames(ctx context.Context, r *dnsx.Resolver, names []string, workers int, ipv6 bool, rec *evidence.Recorder, addErr func(string, ...any)) []resolvedName {
	if workers > len(names) {
		workers = len(names)
	}
	if workers <= 0 {
		return nil
	}
	jobs := make(chan string)
	out := make(chan resolvedName, len(names))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				rn := resolvedName{name: name}
				rrs, rcode, err := r.Lookup(ctx, name, dns.TypeA)
				if err != nil {
					rn.err = err
					out <- rn
					continue
				}
				rn.rcode = dnsx.RCodeString(rcode)
				rn.ips = dnsx.IPs(rrs)
				for _, cn := range dnsx.CNAMEs(rrs) {
					if rn.cname == "" {
						rn.cname = cn
					}
				}
				if ipv6 {
					if rrs6, _, err := r.Lookup(ctx, name, dns.TypeAAAA); err == nil {
						for _, ip := range dnsx.IPs(rrs6) {
							if isV6(ip) {
								rn.aaaa = append(rn.aaaa, ip)
							}
						}
					}
				}
				out <- rn
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, n := range names {
			select {
			case <-ctx.Done():
				return
			case jobs <- n:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var got []resolvedName
	for rn := range out {
		got = append(got, rn)
		data := map[string]any{"ips": rn.ips, "aaaa": rn.aaaa, "cname": rn.cname, "rcode": rn.rcode}
		if rn.err != nil {
			data["error"] = rn.err.Error()
		}
		if _, err := rec.Add("host_resolved", rn.name, "dns", data); err != nil && addErr != nil {
			addErr("evidence write failed: %v", err)
		}
	}
	return got
}

func attemptAXFR(ctx context.Context, r *dnsx.Resolver, domain string, nsNames []string, timeout time.Duration, rec *evidence.Recorder, addErr func(string, ...any), log Logger) []model.AXFR {
	if len(nsNames) > 6 {
		nsNames = nsNames[:6]
	}
	var out []model.AXFR
	for _, ns := range nsNames {
		entry := model.AXFR{NS: ns}
		ips, err := r.ResolveHosts(ctx, ns)
		if err != nil || len(ips) == 0 {
			entry.Error = "cannot resolve nameserver"
			out = append(out, entry)
			continue
		}
		entry.Address = net.JoinHostPort(ips[0], axfrPort)
		log.Verbose("axfr %s @ %s", ns, entry.Address)
		tctx, cancel := context.WithTimeout(ctx, timeout*2)
		records, xerr := r.AXFR(tctx, domain, entry.Address)
		cancel()
		if xerr != nil || len(records) == 0 {
			entry.Error = "refused or empty"
			if xerr != nil && !strings.Contains(strings.ToLower(xerr.Error()), "refused") {
				entry.Error = truncate(xerr.Error(), 160)
			}
		} else {
			entry.OK = true
			entry.Records = dnsx.CanonicalSet(records)
			if len(entry.Records) > 10000 {
				entry.Records = entry.Records[:10000]
			}
			entry.RecordsSHA256 = hashLines(entry.Records)
		}
		data := map[string]any{"ok": entry.OK, "address": entry.Address}
		if entry.OK {
			data["records"] = entry.Records
			data["records_sha256"] = entry.RecordsSHA256
		} else {
			data["error"] = entry.Error
		}
		ev, aerr := rec.Add("axfr", ns, "dns:tcp", data)
		if aerr != nil && addErr != nil {
			addErr("evidence write failed: %v", aerr)
		}
		entry.SHA256 = ev.Hash
		if !entry.OK {
			log.Verbose("axfr %s failed: %s", ns, entry.Error)
		}
		out = append(out, entry)
	}
	return out
}

func probeAll(ctx context.Context, hosts []string, opt probe.Options, workers int, emit func(model.HTTP)) int {
	if workers > len(hosts) {
		workers = len(hosts)
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var wgEmit sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				h := probe.Probe(ctx, host, opt)
				mu.Lock()
				emit(h)
				mu.Unlock()
			}
		}()
	}
	wgEmit.Add(1)
	go func() {
		defer wgEmit.Done()
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- h:
			}
		}
		close(jobs)
	}()
	wg.Wait()
	wgEmit.Wait()
	return len(hosts)
}

func hashLines(lines []string) string {
	h := sha256.New()
	for _, l := range lines {
		_, _ = h.Write([]byte(l))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupeSorted(in []string) []string {
	set := make(map[string]struct{}, len(in))
	for _, s := range in {
		set[s] = struct{}{}
	}
	return sortedSet(set)
}

func isV6(ip string) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var srvServices = []string{
	"_sip._tcp", "_sip._udp", "_sips._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
	"_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp", "_submission._tcp",
	"_autodiscover._tcp", "_caldav._tcp", "_caldavs._tcp", "_carddav._tcp", "_carddavs._tcp",
	"_ldap._tcp", "_kerberos._tcp", "_kpasswd._tcp", "_gc._tcp", "_vlmcs._tcp",
	"_minecraft._tcp", "_http._tcp", "_https._tcp",
}

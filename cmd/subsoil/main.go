// Command subsoil is a low-observable DNS reconnaissance tool for initial
// assessment work. It is a Go re-implementation of the ideas behind
// darryllane/Bluto, with tamper-evident evidence output.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"subsoil/internal/dnsx"
	"subsoil/internal/evidence"
	"subsoil/internal/logx"
	"subsoil/internal/model"
	"subsoil/internal/passive"
	"subsoil/internal/report"
	"subsoil/internal/scan"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		printWelcome(os.Stdout, welcomeColor())
		return 0
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "verify":
		return cmdVerify(args[1:])
	case "version", "--version", "-version", "-V":
		fmt.Printf("subsoil %s (%s %s/%s)\n", model.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	case "help", "-h", "--help":
		printWelcome(os.Stdout, welcomeColor())
		return 0
	}
	if strings.HasPrefix(args[0], "-") {
		return cmdScan(args)
	}
	return cmdScan(args)
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		domain        string
		passiveOnly   bool
		brute         bool
		noBrute       bool
		extended      bool
		wordlists     stringList
		axfr          bool
		httpProbe     bool
		srv           bool
		ptr           bool
		recursive     bool
		ipv6          bool
		resolveIPs    bool
		noResolveIPs  bool
		capture       bool
		workers       int
		qps           int
		timeout       time.Duration
		dnsServers    stringList
		sources       string
		sourceTimeout time.Duration
		outDir        string
		formats       string
		maxHosts      int
		maxHTTP       int
		exclude       string
		noColor       bool
		noSpinner     bool
		quiet         bool
		verbose       bool
		fast          bool
	)

	fs.StringVar(&domain, "d", "", "target domain")
	fs.StringVar(&domain, "domain", "", "target domain")
	fs.BoolVar(&passiveOnly, "passive", false, "passive-only mode")
	fs.BoolVar(&brute, "brute", true, "enable brute forcing")
	fs.BoolVar(&noBrute, "no-brute", false, "disable brute forcing")
	fs.BoolVar(&extended, "e", false, "use the extended wordlist")
	fs.BoolVar(&extended, "extended", false, "use the extended wordlist")
	fs.Var(&wordlists, "w", "wordlist file, directory, .gz or '-' (repeatable)")
	fs.Var(&wordlists, "wordlist", "alias for --wordlist")
	fs.Var(&wordlists, "wordlist-dir", "alias for --wordlist (directory)")
	fs.BoolVar(&axfr, "axfr", false, "attempt zone transfers")
	fs.BoolVar(&httpProbe, "http", false, "probe web services")
	fs.BoolVar(&srv, "srv", false, "enumerate SRV records")
	fs.BoolVar(&ptr, "ptr", false, "reverse-resolve addresses")
	fs.BoolVar(&recursive, "recursive", false, "recursive brute force")
	fs.BoolVar(&ipv6, "ipv6", false, "resolve AAAA records")
	fs.BoolVar(&resolveIPs, "resolve-ips", true, "resolve and display IP addresses for discovered subdomains")
	fs.BoolVar(&noResolveIPs, "no-resolve-ips", false, "do not resolve or display IP addresses for discovered subdomains")
	fs.BoolVar(&capture, "capture", false, "save HTTP response bodies")
	fs.IntVar(&workers, "workers", 20, "DNS workers")
	fs.IntVar(&qps, "qps", 50, "DNS queries per second (0 = unlimited)")
	fs.DurationVar(&timeout, "timeout", 5*time.Second, "per-query timeout")
	fs.Var(&dnsServers, "dns-servers", "DNS servers (comma separated, repeatable, or system; default 1.1.1.1,8.8.8.8)")
	fs.Var(&dnsServers, "dns-server", "alias for --dns-servers")
	fs.Var(&dnsServers, "resolver", "alias for --dns-servers")
	fs.Var(&dnsServers, "resolvers", "alias for --dns-servers")
	fs.StringVar(&sources, "sources", strings.Join(passive.DefaultSources, ","), "passive sources")
	fs.DurationVar(&sourceTimeout, "source-timeout", 30*time.Second, "per-source timeout")
	fs.StringVar(&outDir, "o", "", "output directory")
	fs.StringVar(&outDir, "out", "", "output directory")
	fs.StringVar(&formats, "format", "text,json,md,html", "report formats")
	fs.IntVar(&maxHosts, "max-hosts", 5000, "max names resolved")
	fs.IntVar(&maxHTTP, "max-http", 200, "max HTTP probes")
	fs.StringVar(&exclude, "exclude", "", "exclude regexp")
	fs.BoolVar(&noColor, "no-color", false, "disable colour")
	fs.BoolVar(&noSpinner, "no-spinner", false, "disable the terminal activity spinner")
	fs.BoolVar(&quiet, "quiet", false, "quiet")
	fs.BoolVar(&verbose, "v", false, "per-query and per-source logging")
	fs.BoolVar(&verbose, "verbose", false, "per-query and per-source logging")
	fs.BoolVar(&fast, "fast", false, "raise DNS rate to 250 qps and 50 workers")

	var positional string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positional = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if domain == "" {
		domain = positional
	}
	if domain == "" && fs.NArg() > 0 {
		domain = fs.Arg(0)
	}
	if domain == "" {
		fmt.Fprintln(os.Stderr, "subsoil: a target domain is required")
		fmt.Fprintln(os.Stderr, "try: subsoil example.com   ·   subsoil help")
		return 2
	}

	domain, err := dnsx.ParseName(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
		return 2
	}

	if quiet && verbose {
		fmt.Fprintln(os.Stderr, "subsoil: --quiet and --verbose are mutually exclusive")
		return 2
	}

	if len(wordlists.values) == 0 {
		if env := strings.TrimSpace(os.Getenv("SUBSOIL_WORDLIST")); env != "" {
			for _, p := range filepath.SplitList(env) {
				if p != "" {
					_ = wordlists.Set(p)
				}
			}
		}
	}

	if noResolveIPs {
		resolveIPs = false
	}

	if fast {
		qps = 250
		workers = 50
	}

	if noBrute {
		brute = false
	}
	if passiveOnly {
		brute = false
		axfr = false
		httpProbe = false
		srv = false
		ptr = false
		recursive = false
	}

	var excl *regexp.Regexp
	if exclude != "" {
		excl, err = regexp.Compile(exclude)
		if err != nil {
			fmt.Fprintf(os.Stderr, "subsoil: --exclude: %v\n", err)
			return 2
		}
	}

	otxKey := strings.TrimSpace(os.Getenv("SUBSOIL_OTX_KEY"))
	if otxKey == "" {
		otxKey = strings.TrimSpace(os.Getenv("OTX_API_KEY"))
	}
	sourceList := parseList(sources)
	for _, s := range sourceList {
		if s == "all" {
			sourceList = append([]string(nil), passive.KnownSources...)
			break
		}
	}
	for _, s := range sourceList {
		if s == "none" || s == "" {
			continue
		}
		if _, ok := passive.NewSource(s, passive.Options{OTXKey: otxKey}); !ok {
			fmt.Fprintf(os.Stderr, "subsoil: unknown source %q (known: %s)\n", s, strings.Join(passive.KnownSources, ", "))
			return 2
		}
	}
	sourceList = filterStrings(sourceList, func(s string) bool { return s != "" && s != "none" })

	dnsSpec := strings.TrimSpace(dnsServers.String())
	if dnsSpec == "" {
		dnsSpec = "1.1.1.1,8.8.8.8"
	}
	resolverList, err := dnsx.ParseServers(dnsSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
		return 2
	}
	formatList := dedupe(parseList(formats))
	if len(formatList) == 0 {
		formatList = []string{"text"}
	}
	for _, f := range formatList {
		switch f {
		case "text", "json", "md", "markdown", "html":
		default:
			fmt.Fprintf(os.Stderr, "subsoil: unknown format %q (want text, json, md, html)\n", f)
			return 2
		}
	}

	if outDir == "" {
		outDir = fmt.Sprintf("subsoil-%s-%s", domain, time.Now().UTC().Format("20060102-150405"))
	}

	var logOut io.Writer = os.Stderr
	if quiet {
		logOut = io.Discard
	}
	log := logx.New(logOut, verbose)
	if !quiet {
		p := painter{on: colorFor(os.Stderr)}
		mode := "standard"
		if passiveOnly {
			mode = "passive-only"
		}
		fmt.Fprintf(os.Stderr, "\n  %s  %s\n", p.bold("Subsoil "+model.Version), p.dim("· low-observable DNS reconnaissance"))
		fmt.Fprintf(os.Stderr, "  %s %s  %s %s  %s %d qps  %s %d workers\n",
			p.dim("target"), domain, p.dim("·"), mode, p.dim("·"), qps, p.dim("·"), workers)
	}
	log.Verbose("config: target=%s resolvers=%s sources=%s workers=%d qps=%d timeout=%s resolve_ips=%t",
		domain, strings.Join(resolverList, ","), strings.Join(sourceList, ","), workers, qps, timeout, resolveIPs)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var spin *spinner
	if !quiet && !noSpinner && os.Getenv("TERM") != "dumb" && isTerminal(os.Stderr) {
		spin = newSpinner(os.Stderr, "scanning "+domain, !noColor && colorFor(os.Stderr))
		log.SetActivity(spin)
		spin.Start()
	}

	res, err := scan.Run(ctx, scan.Options{
		Domain:        domain,
		OutDir:        outDir,
		PassiveOnly:   passiveOnly,
		Brute:         brute,
		Extended:      extended,
		WordlistPaths: wordlists.values,
		AXFR:          axfr,
		HTTP:          httpProbe,
		SRV:           srv,
		PTR:           ptr,
		Recursive:     recursive,
		IPv6:          ipv6,
		NoIPLookup:    !resolveIPs,
		Capture:       capture,
		Workers:       workers,
		QPS:           qps,
		Timeout:       timeout,
		Resolvers:     resolverList,
		Sources:       sourceList,
		SourceTimeout: sourceTimeout,
		OTXKey:        otxKey,
		MaxHosts:      maxHosts,
		MaxHTTP:       maxHTTP,
		Exclude:       excl,
		Log:           log,
	})
	if spin != nil {
		spin.Stop()
		log.SetActivity(nil)
	}
	scanErr := err
	if scanErr != nil && res == nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", scanErr)
		return 1
	}
	if scanErr != nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", scanErr)
	}

	files, werr := report.Write(res, outDir, formatList)
	if werr != nil {
		fmt.Fprintf(os.Stderr, "subsoil: writing report: %v\n", werr)
		return 1
	}
	abs, _ := filepath.Abs(outDir)
	log.Verbose("report files: %s", strings.Join(files, ", "))

	if !quiet {
		color := !noColor && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)
		report.RenderText(os.Stdout, res, color)
		fmt.Printf("  %-12s %s\n", "output", abs)
		fmt.Printf("  %-12s %s\n", "files", strings.Join(files, ", "))
		fmt.Println()
	}

	// A cancelled scan still produces a valid partial report.
	if ctx.Err() != nil {
		return 130
	}
	if scanErr != nil {
		return 1
	}
	return 0
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: subsoil verify <evidence.jsonl>")
		return 2
	}
	path := fs.Arg(0)
	rep, err := evidence.VerifyFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "subsoil: %v\n", err)
		return 1
	}
	fmt.Printf("file        %s\n", rep.File)
	fmt.Printf("records     %d\n", rep.Records)
	fmt.Printf("root sha256 %s\n", rep.RootSHA256)
	fmt.Printf("file sha256 %s\n", rep.FileSHA256)
	ok := rep.OK
	sidecarChecked := false
	if sidecar, serr := os.ReadFile(path + ".sha256"); serr == nil {
		if want := strings.Fields(string(sidecar)); len(want) > 0 {
			sidecarChecked = true
			if want[0] == rep.FileSHA256 {
				fmt.Printf("sidecar     matches %s.sha256\n", filepath.Base(path))
			} else {
				fmt.Printf("sidecar     MISMATCH (file says %s)\n", want[0])
				ok = false
			}
		}
	}
	if !rep.OK {
		fmt.Println("chain       BROKEN")
		for _, e := range rep.Errors {
			fmt.Printf("  - %s\n", e)
		}
		return 1
	}
	fmt.Println("chain       OK — every record matches its hash and the previous record")
	if !ok && sidecarChecked {
		fmt.Println("verdict     FAILED — the evidence log is intact but does not match its .sha256 sidecar")
		return 1
	}
	fmt.Println("verdict     OK")
	return 0
}

func parseList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func filterStrings(in []string, keep func(string) bool) []string {
	out := in[:0]
	for _, s := range in {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}

func welcomeColor() bool { return colorFor(os.Stdout) }

func colorFor(f *os.File) bool {
	return os.Getenv("NO_COLOR") == "" && isTerminal(f)
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

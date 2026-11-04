package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/subsll/subsoil/internal/model"
)

// banner is the shadow-font wordmark shown by the welcome screen. Keep it
// narrow enough for an 80-column terminal.
var banner = []string{
	`███████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██╗██╗`,
	`██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗██║██║`,
	`███████╗██║   ██║██████╔╝███████╗██║   ██║██║██║`,
	`╚════██║██║   ██║██╔══██╗╚════██║██║   ██║██║██║`,
	`███████║╚██████╔╝██████╔╝███████║╚██████╔╝██║███████╗`,
	`╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝╚══════╝`,
}

type painter struct{ on bool }

func (p painter) wrap(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return code + s + "\x1b[0m"
}

func (p painter) bold(s string) string   { return p.wrap("\x1b[1m", s) }
func (p painter) dim(s string) string    { return p.wrap("\x1b[2m", s) }
func (p painter) cyan(s string) string   { return p.wrap("\x1b[36m", s) }
func (p painter) green(s string) string  { return p.wrap("\x1b[32m", s) }
func (p painter) yellow(s string) string { return p.wrap("\x1b[33m", s) }

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// printWelcome renders the interactive-less welcome screen: a wordmark, the
// command surface, quick-start recipes and the evidence/safety notes.
func printWelcome(w io.Writer, color bool) {
	p := painter{on: color}

	fmt.Fprintln(w)
	for _, line := range banner {
		fmt.Fprintln(w, "  "+p.bold(p.cyan(line)))
	}
	fmt.Fprintf(w, "  %s\n\n", p.dim("Subsoil  ·  low-observable DNS reconnaissance  ·  v"+model.Version))

	const cmdW, descW = 20, 38
	inner := cmdW + descW + 3
	rule := strings.Repeat("─", inner)
	fmt.Fprintf(w, "  %s\n", p.dim("╭"+rule+"╮"))
	row := func(cmd, desc string) {
		fmt.Fprintf(w, "  %s %s %s %s\n",
			p.dim("│"), p.bold(padRight(cmd, cmdW)), padRight(desc, descW), p.dim("│"))
	}
	row("scan <domain>", "run a reconnaissance scan")
	row("verify <evidence>", "verify the SHA-256 chain")
	row("version", "print build and platform")
	row("help", "show this screen")
	fmt.Fprintf(w, "  %s\n", p.dim("╰"+rule+"╯"))

	fmt.Fprintf(w, "\n  %s\n", p.bold("QUICK START"))
	examples := [][2]string{
		{"subsoil example.com", "standard first pass"},
		{"subsoil example.com --passive", "certificate names, no DNS packets"},
		{"subsoil example.com --srv --http", "service records and web probes"},
		{"subsoil example.com -e --axfr", "deeper and louder"},
		{"subsoil example.com --verbose", "show every DNS query"},
	}
	for _, e := range examples {
		fmt.Fprintf(w, "    %s %s\n", p.cyan(padRight(e[0], 34)), p.dim(e[1]))
	}

	fmt.Fprintf(w, "\n  %s\n", p.bold("COMMON FLAGS"))
	flags := [][2]string{
		{"-d, --domain <name>", "target domain (or positional)"},
		{"--passive", "passive-only: no DNS packets sent"},
		{"-e, --extended", "20,000-word dictionary"},
		{"-w, --wordlist <path>", "file, directory, .gz or -"},
		{"--axfr / --http", "enable the active checks"},
		{"--dns-servers <list>", "resolvers; repeatable, or system"},
		{"-v, --verbose", "per-query and per-source logging"},
		{"--fast", "250 qps, 50 workers (noisier)"},
		{"--no-resolve-ips", "hide subdomain IP lookups"},
		{"--no-spinner", "disable the activity spinner"},
		{"-o, --out <dir>", "output directory"},
	}
	for _, f := range flags {
		fmt.Fprintf(w, "    %s %s\n", padRight(f[0], 22), p.dim(f[1]))
	}
	fmt.Fprintf(w, "    %s\n", p.dim("every flag:  subsoil scan --help"))

	fmt.Fprintf(w, "\n  %s\n", p.bold("EVIDENCE"))
	fmt.Fprintf(w, "    Every finding is SHA-256 hashed into a tamper-evident chain.\n")
	fmt.Fprintf(w, "    Verify a run:  %s\n", p.green("subsoil verify <scan-dir>/evidence.jsonl"))

	fmt.Fprintf(w, "\n  %s\n", p.yellow("Use only against systems you own or are explicitly authorised to test."))
	fmt.Fprintf(w, "  %s\n\n", p.dim("tip: start with --passive; it sends no DNS packets at all."))
}

# Changelog

All notable changes to Subsoil are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [1.5.0]

### Added

- Opt-in `--email-analysis` SPF, DKIM and DMARC posture scoring (0–100 with an
  A–F grade), available in terminal, Markdown, HTML, JSON, `email-analysis.csv`
  and the hash-chained evidence log.
- DKIM selector lookups with a conservative default selector list and
  `--dkim-selectors` for provider-specific selectors.
- Transparent SPF, DKIM and DMARC component scores and actionable configuration
  issues, including SPF lookup limits, permissive `+all`, missing DMARC
  reporting, relaxed alignment and revoked or unverifiable DKIM keys.

## [1.4.0]

### Added

- `subsoil compare <file> --case <case-dir|evidence.jsonl>` computes a file's
  SHA-256, verifies the case chain and reports whether the digest already appears
  in the evidence. Supports `--hash`, `--json`, directory or file case paths, and
  sidecar validation.

### Fixed

- DNS queries reuse a bounded pool of persistent UDP connections per resolver
  instead of opening a fresh socket for every query. Sockets rotate after 512
  queries to retain source-port diversity. This prevents large brute-force runs
  from filling small-router NAT/conntrack tables and disrupting normal browsing.

## [1.3.3]

### Fixed

- Published the canonical Go module path `github.com/subsll/subsoil`.

## [1.3.2]

### Added

- Interactive `graph.html` force-directed entity graph connecting domains, DNS
  records, subdomains, IPs, nameservers, mail/SRV targets, HTTP/TLS, passive
  sources, PTR, AXFR and wildcard findings.
- A terminal activity spinner while a scan is running, with the current scan
  phase (baseline DNS, passive sources, brute force, probes, etc.). It is hidden
  for non-TTY output and can be disabled with `--no-spinner` or `--quiet`.

### Fixed

- OTX connections that close before a response (`EOF`) are retried once.
- OTX uses HTTP/1.1 and a stable `subsoil/<version>` User-Agent instead of a
  random browser UA.

## [1.3.1]

### Fixed

- OTX passive DNS now requires authentication. Added `SUBSOIL_OTX_KEY` (or
  `OTX_API_KEY`) support via the `X-OTX-API-KEY` header and removed OTX from the
  default sources. Missing keys now produce a clear error instead of an
  anonymous HTTP 403.
- OTX gateway errors are no longer retried (single attempt), OTX requests are
  capped at 15s, and the default per-source timeout is reduced from 90s to 30s.

## [1.3.0]

### Added

- `--resolve-ips` / `--no-resolve-ips` toggle for subdomain IP resolution.
  Disabling it skips passive-name lookups and hides brute-force addresses in
  reports and evidence; PTR is skipped.

## [1.2.0]

### Added

- Multi-source wordlists: repeatable `-w/--wordlist`, directories, gzip files,
  stdin (`-w -`) and the `SUBSOIL_WORDLIST` environment default.
- `--wordlist-dir` alias and source/label logging.
- Early wordlist validation, so a bad path fails before any DNS work.
- Warning when `--max-hosts` truncates a large custom wordlist.

## [1.1.1]

### Fixed

- Brute-force progress now counts every attempt, including wildcard-filtered
  and NXDOMAIN answers. Previously a wildcard-heavy run could look hung.
- Added percentage, hit count and ETA to brute-force progress.
- Added AXFR start/end logging.

### Added

- `--fast` preset: 250 qps with 50 workers.

## [1.1.0]

### Added

- `--verbose` per-query, per-source and per-probe logging.
- `--dns-servers` with repeatable/comma-separated endpoints, IPv6, ports and
  `system`; `--resolver` and `--resolvers` remain aliases.
- DNS failover on timeout, `REFUSED` and `SERVFAIL`.

## [1.0.0]

### Added

- Passive sources: crt.sh, Cert Spotter, AlienVault OTX and HackerTarget.
- DNS baseline: A, AAAA, NS, MX, TXT, SOA, CAA, SPF and DMARC.
- Wildcard detection and wildcard-aware brute forcing.
- AXFR, SRV, PTR, one-level recursion and HTTP(S) probing.
- SHA-256 hash-chained evidence log, verifier and checksum manifest.
- Terminal, TXT, JSON, Markdown, HTML and CSV reports.
- Static Linux builds for amd64, arm64, armv7 and 386.

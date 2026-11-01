# Changelog

All notable changes to Subsoil are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

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

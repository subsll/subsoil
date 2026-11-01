# Subsoil

**Low-observable DNS reconnaissance for the first ten minutes of an assessment.**

![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)

Subsoil is a single static Go binary for initial external recon: passive subdomain
collection, DNS baseline, wildcard-aware brute forcing, zone-transfer checks, SRV/PTR
enumeration and one-shot HTTP(S) probing. Every finding is written to a SHA-256
hash-chained evidence log so results can be verified later.

```text
$ subsoil scan example.com --no-brute --verbose
  Subsoil 1.3.0  ·  low-observable DNS reconnaissance
  target example.com  ·  standard  ·  50 qps  ·  20 workers

[v] config: target=example.com resolvers=1.1.1.1:53 sources=crt.sh,certspotter,otx workers=20 qps=50 timeout=5s
[v] dns A example.com @1.1.1.1:53 -> NOERROR, 2 answer(s), 13ms
[v] dns MX example.com @1.1.1.1:53 -> NOERROR, 1 answer(s), 15ms
[*] passive sources: crt.sh, certspotter, otx
```

> **Authorised use only.** Use Subsoil against systems you own or have explicit
> written permission to test. The default mode is deliberately quiet, but DNS
> brute forcing and zone-transfer attempts are active techniques.

---

## Highlights

- **Passive first** — certificate transparency and passive-DNS sources before any
  packet goes near the target.
- **DNS baseline** — A, AAAA, NS, MX, TXT, SOA, CAA, SPF and DMARC.
- **Wildcard-aware brute forcing** — detects wildcard DNS, fingerprints the answers
  and discards false positives.
- **Optional active checks** — AXFR, SRV, PTR, one-level recursion and HTTP(S)
  probing with TLS metadata.
- **Tamper-evident evidence** — per-finding SHA-256 hashes, a hash chain, a
  verifier and a checksum manifest.
- **Reports** — terminal, TXT, JSON, Markdown, standalone HTML, `subdomains.txt`
  and `hosts.csv`.
- **One portable binary** — no runtime, no Python, no external libraries.

---

## Install

### Prebuilt binaries

Download the latest Linux release from the repository's **Releases** page. Each
release contains static binaries for amd64, arm64, armv7 and 386, plus
`SHA256SUMS`.

```sh
sha256sum -c SHA256SUMS
chmod +x subsoil_<version>_linux_amd64
./subsoil_<version>_linux_amd64 version
```

### Build from source

Requires Go 1.25 or newer.

```sh
git clone <repository-url>
cd subsoil
go test ./...
make build          # dist/subsoil for the current platform
make linux          # static Linux binaries
make checksums      # dist/SHA256SUMS
```

The module path is `subsoil`. If you publish this under GitHub and want
`go install github.com/<owner>/subsoil/cmd/subsoil@latest` to work, update
`module` in `go.mod` and the `subsoil/...` imports first. See
[CONTRIBUTING.md](CONTRIBUTING.md#module-path).

---

## Quick start

```sh
subsoil                                      # welcome screen

# Passive only: no DNS packets leave your machine.
subsoil scan example.com --passive

# Standard first pass.
subsoil scan example.com

# Add service and web checks.
subsoil scan example.com --srv --ptr --http

# Deeper and faster: 20k words, AXFR attempts, recursion, body capture.
subsoil scan example.com -e --axfr --recursive --http --capture --fast

# Verify a run later.
subsoil verify subsoil-example.com-<timestamp>/evidence.jsonl
```

`subsoil example.com` is shorthand for `subsoil scan example.com`. Run `subsoil`
with no arguments (or `subsoil help`) for the ASCII welcome screen, command
reference and quick-start recipes.

---

## What a scan does

1. **Passive collection** runs first: certificate transparency and passive-DNS
   sources are queried in parallel. Nothing is sent to the target or its DNS
   servers.
2. **DNS baseline** resolves the apex records and `_dmarc`, with a timeout and
   rate limit.
3. **Wildcard detection** resolves random labels. If they answer, the fingerprint
   is recorded and matching brute-force results are filtered.
4. **Brute force** resolves `word.domain` with a worker pool, paced by `--qps`.
5. **Optional active checks** — AXFR, SRV, PTR, recursion, HTTP(S) — run only when
   requested.
6. **Evidence** is appended for each observation, then the log is closed and its
   root hash is recorded in the reports.

In `--passive` mode steps 2–5 are skipped entirely. You still get passive names,
marked resolved or unresolved where known, plus source errors in the evidence log.

---

## Low-observable by design

"No tool is undetectable" is worth saying plainly. Subsoil keeps the target's
exposure to **your** address at zero in the default path:

- **Public recursive resolvers by default** (`1.1.1.1`, `8.8.8.8`). Authoritative
  servers see the resolver, not you.
- **No EDNS Client Subnet.** Subsoil sends EDNS0 for larger answers but never an
  ECS option.
- **Paced, jittered queries.** Default 50 qps with ±25% timing jitter, not an
  unbounded burst.
- **Bounded concurrency.** A worker pool caps parallel lookups.
- **No direct target contact by default.** `--axfr` and `--http` are the only
  features that talk to the target directly; both are opt-in.
- **Browser-like HTTP fingerprints.** One request per host, current browser
  User-Agent, no crawling.
- **No telemetry.** The only outbound traffic is DNS, the passive sources you
  enable, and opted-in HTTP probes.

### What still leaks

| Observer | What it can see |
| --- | --- |
| crt.sh / Cert Spotter / OTX / HackerTarget | Your IP and the domain you asked about |
| Your recursive resolver | Every name you looked up, and your IP |
| Authoritative nameservers | The resolver's IP and the query pattern |
| Target web server (`--http`) | Your IP, TLS fingerprint, User-Agent |
| Authoritative nameserver (`--axfr`) | Your IP and the AXFR attempt |

Rate limiting reduces the signal; it does not erase it.

---

## Evidence and SHA-256 proof

Every observation is one line of `evidence.jsonl`:

```json
{"seq":2,"time":"2026-11-01T18:28:22.313844Z","type":"dns_record","target":"example.com","source":"dns","prev_hash":"acf7d5cd...","data":{"qtype":"A","rcode":"NOERROR","rrs":["example.com.\t0\tIN\tA\t203.0.113.10"],"rrs_sha256":"21bcc691..."},"hash":"587b7978..."}
```

- `hash` is SHA-256 over the canonical JSON of
  `{seq, time, type, target, source, prev_hash, data}`.
- `prev_hash` links each record to its predecessor. Editing, deleting or
  reordering a record breaks the chain at that point.
- `data.rrs_sha256` is SHA-256 over the sorted canonical RRset lines (TTL zeroed).
- The **chain root** is the hash of the last record; it is printed in the report
  and stored in `report.json`.

| Artefact | Hash |
| --- | --- |
| Subdomain / host | SHA-256 of its `host` evidence record |
| DNS RRset | `rrs_sha256`, plus the SHA-256 of the evidence line |
| Zone transfer | SHA-256 over the sorted transferred RRset |
| HTTP response | SHA-256 of the response body actually read (cap 2 MiB) |
| Whole run | Chain root plus file hashes in `SHA256SUMS` |

```sh
subsoil verify subsoil-example.com-<timestamp>/evidence.jsonl
```

```text
records     19
root sha256 8810e6f3...
file sha256 110b286d...
sidecar     matches evidence.jsonl.sha256
chain       OK — every record matches its hash and the previous record
verdict     OK
```

The format, canonicalisation rules and an independent Python verifier are in
[docs/evidence.md](docs/evidence.md).

A hash proves the recorded bytes were not altered after the scan. It does not
prove DNS was truthful, that a server served the same content to every client, or
that the target was authorised to be scanned. Sign `SHA256SUMS` if you need
third-party attestation.

---

## Output

```text
subsoil-example.com-20260101-120000/
├── report.txt               terminal report
├── report.md                Markdown evidence report
├── report.html              standalone HTML report
├── report.json              complete machine-readable result
├── subdomains.txt           one name per line
├── hosts.csv                name, status, addresses, hidden flag, sources, SHA-256
├── evidence.jsonl           hash-chained proof log
├── evidence.jsonl.sha256    detached file hash
├── bodies/                  HTTP bodies (only with --capture)
└── SHA256SUMS               manifest for every file above
```

---

## Flags

```text
-d, --domain <name>      target domain (or positional argument)
    --passive            passive-only: send no DNS packets
    --brute              brute force (default true)
    --no-brute           disable brute force
-e, --extended           use the 20k embedded wordlist
-w, --wordlist <path>    file, directory, .gz, or - for stdin (repeatable)
    --wordlist-dir       alias for --wordlist
    --axfr               attempt zone transfers
    --http               probe HTTP(S)
    --srv                enumerate common SRV records
    --ptr                reverse-resolve discovered addresses
    --recursive          brute one level under discovered hosts
    --ipv6               also resolve AAAA
    --resolve-ips        resolve/display IPs for discovered names (default true)
    --no-resolve-ips     skip passive-name resolution and hide brute-force IPs
    --workers <n>        DNS workers (default 20)
    --qps <n>            queries/second, 0 = unlimited (default 50)
    --fast               raise the rate to 250 qps and 50 workers
    --timeout <dur>      per-query timeout (default 5s)
    --dns-servers <list> DNS servers (repeatable, comma separated, or system)
    --sources <list>     crt.sh, certspotter, otx, hackertarget, all, none
    --source-timeout <d> per-source timeout (default 90s)
    --format <list>      text,json,md,html (default all)
-o, --out <dir>          output directory
    --max-hosts <n>      cap on names resolved/reported (default 5000)
    --max-http <n>       cap on HTTP probes (default 200)
    --capture            save HTTP response bodies
    --exclude <regexp>   drop names matching a pattern
    --quiet              no progress or terminal report
    --no-color           disable ANSI colour
-v, --verbose            log every DNS query, passive request and probe
```

Exit codes: `0` success, `1` error or broken evidence, `2` usage error,
`130` interrupted (a partial report is still written).

---

## DNS servers

`--dns-servers` accepts IPv4/IPv6 addresses, optional ports, hostnames, a
comma-separated list, repeated flags, or `system`. The default is
`1.1.1.1,8.8.8.8`.

```sh
subsoil scan example.com --dns-servers 9.9.9.9
subsoil scan example.com --dns-servers 1.1.1.1:53,8.8.8.8:53
subsoil scan example.com --dns-servers system
subsoil scan example.com --dns-servers 10.0.0.53:5353 --dns-servers 10.0.0.54
```

Servers are rotated per query; on timeout, `REFUSED` or `SERVFAIL` the next
server is tried. `--resolver`, `--resolvers` and `--dns-server` remain aliases.
Only classic DNS over UDP/TCP is supported; DoH/DoT URLs are not accepted.

---

## Custom wordlists

`-w/--wordlist` accepts text files, gzip files, directories of lists, and `-` for
stdin. Repeat the flag to merge lists; labels are normalised, validated and
de-duplicated in first-seen order.

```sh
subsoil scan example.com -w /opt/wordlists/subdomains.txt
subsoil scan example.com -w ./lists/ -w ./extra-labels.txt
subsoil scan example.com -w ~/wordlists/raft-medium.txt.gz
cat words.txt | subsoil scan example.com -w -
```

Directory mode is non-recursive and loads `.txt`, `.lst`, `.list`, `.wordlist`,
`.dict`, `.words` and `.gz` files.

Set a default location:

```sh
export SUBSOIL_WORDLIST="$HOME/wordlists/subdomains.txt"
subsoil scan example.com
```

A custom list takes precedence over `-e`. A missing or empty source fails fast
with exit code `1`.

---

## IP lookup toggle

By default (`--resolve-ips`) Subsoil resolves every discovered subdomain to
A/AAAA addresses and includes them in the reports. `--no-resolve-ips` turns that
off:

```sh
subsoil scan example.com --no-resolve-ips
```

What changes:

- passive names are not resolved, so no extra DNS lookups are made for them
- brute force still resolves names internally to detect them, but IPs are
  omitted from host records, evidence, CSV and reports
- `--ptr` is skipped with a warning
- apex A/AAAA records from the initial DNS baseline are still collected
- raw AXFR output, if enabled, is unaffected
- `--http` probes still connect by hostname; their IPs are not reported

The JSON result records `"resolve_ips": false` and hosts carry
`"ips_hidden": true`; the CSV has an `ips_hidden` column.

## Verbose output

`-v/--verbose` logs every DNS query with resolver, result, answer count and
latency, plus passive-source requests, HTTP probes and wordlist sources. It is
incompatible with `--quiet`.

```sh
subsoil scan example.com --verbose
```

```text
[v] dns A example.com @1.1.1.1:53 -> NOERROR, 2 answer(s), 13ms
[v] passive certspotter: GET https://api.certspotter.com/v1/issuances?...
```

---

## Performance

The default is 50 qps, which takes about 100 seconds for 5,000 words and about
6m24s for the 20k list. `--fast` raises the rate to 250 qps with 50 workers
(about 77 seconds for 19k words) at the cost of a much louder query pattern.
You can also tune `--qps` and `--workers` yourself; keep workers around `qps/2`.
Passive sources usually dominate wall time on small scans; `--source-timeout 25s`
keeps a slow CT provider from stretching a run.

---

## Compared with the original Bluto

Subsoil is an independent Go re-implementation of the DNS reconnaissance ideas
popularised by [Bluto](https://github.com/darryllane/Bluto), a Python 2.7 tool
from 2016.

| | Bluto (Python 2.7) | Subsoil |
| --- | --- | --- |
| Runtime | Python 2.7 + pip dependencies | one static Go binary |
| Passive names | NetCraft | crt.sh, Cert Spotter, OTX, HackerTarget |
| Brute force | 20k Alexa, subprocess parallel | SecLists 5k/20k/custom, worker pool, paced |
| Wildcard | detect + special mode | detect + fingerprint filtering |
| AXFR | yes | yes, opt-in |
| Email / staff / breach | Bing, Google, LinkedIn, EmailHunter, HIBP | intentionally not implemented |
| Reports | HTML | TXT, JSON, Markdown, HTML, CSV |
| Integrity | none | SHA-256 chain + verifier |
| Detection posture | random UA, connection per request | passive-first, public resolvers, no ECS, jitter |

The email, employee and breach features are deliberately omitted: they are
fragile, frequently violate provider terms, and process personal data that
initial DNS recon does not need.

---

## Limits

- **ASCII domains only.** Pass IDN targets as punycode.
- **Unresolved names are kept and marked.** Certificate transparency contains
  stale names; Subsoil reports them as `unresolved`.
- **Wildcard heuristic.** A real host sharing every address with the wildcard
  record is treated as a false positive. The count is reported.
- **HTTP body hashing is capped** at 2 MiB; `body_len` says how much was read.
- **AXFR uses port 53** and only one address per nameserver.
- **No screenshots, JS rendering or crawling.** One request per host.
- **Passive source uptime is outside our control.** crt.sh returns 502s under
  load and OTX rate-limits anonymous clients; failures are recorded as evidence.

---

## Development

```text
cmd/subsoil/          CLI, welcome screen and flags
internal/scan/        orchestration and evidence emission
internal/dnsx/        resolver, RR canonicalisation, AXFR
internal/brute/       worker pool and wildcard filtering
internal/passive/     crt.sh, Cert Spotter, OTX, HackerTarget
internal/probe/       HTTP(S) probing
internal/evidence/    hash-chained log and verifier
internal/report/      terminal, JSON, Markdown, HTML, CSV
internal/wordlist/    embedded and user-supplied dictionaries
```

```sh
go test ./...              # unit + integration tests against an in-process DNS server
go test -race ./...        # concurrency checks
go vet ./...
gofmt -w .
```

Tests never need internet access: the integration suite starts an authoritative
DNS server, mock HTTP servers and fixture passive sources locally.

### Module path

The module is declared as `subsoil` so the tree builds without a hosting account.
To publish on GitHub and support `go install`, change it to your repository path:

```sh
# Example: github.com/your-name/subsoil
find . -name '*.go' -print0 | xargs -0 perl -pi -e 's{"subsoil/}{"github.com/your-name/subsoil/}g'
perl -pi -e 's{^module subsoil$}{module github.com/your-name/subsoil}' go.mod
```

Also update the `-X subsoil/internal/model.Version` path in `Makefile` and
`.github/workflows/release.yml`.

CI runs formatting, vet, race tests and a static build for pushes to `main` or
`master` and for pull requests. Pushing a `v*` tag builds the four Linux binaries and attaches them to a
GitHub release with `SHA256SUMS`. See [CHANGELOG.md](CHANGELOG.md) for release
history and [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and pull requests are welcome.
For security issues, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.

---

## License

MIT — see [LICENSE](LICENSE).

Subsoil is not affiliated with the original Bluto author. Wordlists are derived
from [SecLists](https://github.com/danielmiessler/SecLists) (MIT); see
[NOTICE](NOTICE). DNS wire handling uses
[miekg/dns](https://github.com/miekg/dns).

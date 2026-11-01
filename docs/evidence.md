# Evidence format

`evidence.jsonl` is the proof artefact of a scan. It is an append-only,
hash-chained log: each line commits to its own contents **and** to every line
before it. `subsoil verify` checks it; the format is simple enough to verify with
a few lines of Python.

## Goals

- Every finding is individually hashed, so a report row can be tied back to a
  specific observation.
- Changing one byte of one record is detectable.
- Deleting or reordering records is detectable.
- The verifier needs no key material and no network access.

## File

UTF-8, one compact JSON object per line, newline terminated. Field order is
fixed:

```json
{"seq":2,"time":"2026-11-01T18:28:22.313844Z","type":"dns_record","target":"example.com","source":"dns","prev_hash":"acf7...","data":{"qtype":"A","rcode":"NOERROR","rrs":["example.com.\t0\tIN\tA\t203.0.113.10"],"rrs_sha256":"21bc..."},"hash":"587b..."}
```

| Field | Meaning |
| --- | --- |
| `seq` | 1-based record number, contiguous |
| `time` | observation time, UTC, RFC 3339 with nanoseconds |
| `type` | `scan_start`, `dns_record`, `subdomain`, `host_resolved`, `host`, `wildcard`, `axfr`, `srv`, `ptr`, `http`, `source_error`, `scan_end` |
| `target` | the name, address or URL the observation is about |
| `source` | `dns`, `dns:tcp`, `http`, `brute`, `passive:<provider>`, `subsoil` |
| `prev_hash` | hash of the previous record; omitted for `seq` 1 |
| `data` | type-specific object (see below) |
| `hash` | SHA-256 of the canonical payload |

### `data` by type

| Type | Data |
| --- | --- |
| `scan_start` | version, resolvers, sources, passive_only, brute, started |
| `dns_record` | qtype, rcode, rrs (canonical strings), rrs_sha256 |
| `subdomain` | source, and ips/aaaa/cname for brute-force hits, or `ips_hidden` |
| `host_resolved` | ips, aaaa, cname, rcode, error |
| `host` | ips, aaaa, cname, sources, resolved, rcode, ips_hidden |
| `wildcard` | enabled, probes, ips, cnames |
| `axfr` | ok, address, records, records_sha256, error |
| `srv` | target, port, priority, weight |
| `ptr` | names |
| `http` | url, status, server, title, content_type, redirects, tls, body_sha256, body_len, body_file, error |
| `source_error` | error |

## Canonical payload

The hash is computed over exactly these bytes, with **no trailing newline**:

```
{"seq":<int>,"time":"<RFC3339Nano>","type":"<type>","target":"<target>","source":"<source>","prev_hash":"<hash>","data":<data JSON>}
```

Rules:

1. Field order is exactly `seq`, `time`, `type`, `target`, `source`,
   `prev_hash`, `data`.
2. `prev_hash` is omitted entirely for the first record.
3. `data` is the JSON value exactly as stored: compact, object keys sorted
   lexicographically, HTML escaping disabled (`<`, `>`, `&` are literal),
   integers only.
4. `hash` is the lowercase hex SHA-256 of the UTF-8 bytes above.

Go's encoder escapes U+2028 and U+2029 even with HTML escaping disabled. In
practice DNS names and record data are ASCII; if you re-implement the verifier,
escape those two runes the same way (`\u2028`, `\u2029`).

## Chain rules

- `seq` starts at 1 and increases by exactly 1 per record.
- `prev_hash` equals the previous record's `hash`.
- The **root hash** is the last record's `hash`.
- An empty log is invalid.

## Verify with Subsoil

```sh
subsoil verify evidence.jsonl
```

It recomputes each payload hash, checks the links and sequence, and compares
the file hash with `evidence.jsonl.sha256` when that sidecar exists. Exit code
`1` on any mismatch, with the offending line number.

## Verify with Python

This is the same algorithm, independent of the Go code:

```python
import hashlib, json, sys

path = sys.argv[1]
prev, seq = "", 0

for line in open(path, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    rec = json.loads(line)
    seq += 1
    assert rec["seq"] == seq, f"sequence gap at {seq}"
    assert rec.get("prev_hash", "") == prev, f"broken link at {seq}"

    payload = {
        "seq": rec["seq"],
        "time": rec["time"],
        "type": rec["type"],
        "target": rec["target"],
        "source": rec["source"],
    }
    if rec.get("prev_hash"):
        payload["prev_hash"] = rec["prev_hash"]
    payload["data"] = rec["data"]

    canon = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canon.encode()).hexdigest()
    assert digest == rec["hash"], f"hash mismatch at {seq}"
    prev = digest

print(f"OK: {seq} records, root {prev}")
```

Check the sidecar too:

```python
import hashlib
want = open("evidence.jsonl.sha256").read().split()[0]
got = hashlib.sha256(open("evidence.jsonl", "rb").read()).hexdigest()
assert want == got
```

## RRset hashing

For a DNS answer, `data.rrs` contains canonical record strings and
`data.rrs_sha256` hashes them:

1. Copy the record, set TTL to 0, lowercase the owner name, set class to IN.
2. Render with the standard presentation format (tab separated).
3. Sort and de-duplicate the strings.
4. `rrs_sha256 = SHA-256(concat(line + "\n"))`.

Zeroing the TTL means the proof does not change when a resolver's cache ages.
The RRset hash is a convenience fingerprint; the chain hashes the whole `data`
object, so it is covered too.

## HTTP body hashing

`body_sha256` covers exactly the first `body_len` bytes that were read, up to a
2 MiB cap. `--capture` also stores those bytes under `bodies/`. A hash proves
the bytes did not change after the scan; it does not prove the server returns
the same bytes to every client.

## What a hash proves, and what it does not

**Proves:** the log existed in this exact form at the time you received it, the
record was not edited afterwards, and no record was removed or reordered.

**Does not prove:** that DNS was truthful (a resolver can be spoofed or
compromised), that the server was not serving per-client content, or that the
target was authorised to be scanned. Pair the log with a signed manifest
(`gpg --detach-sign SHA256SUMS`) or an RFC 3161 timestamp if you need
third-party attestation of *when* it existed.

## Chain of custody

1. Deliver `evidence.jsonl`, `evidence.jsonl.sha256`, `SHA256SUMS`, and the
   report files together.
2. Sign `SHA256SUMS` with a key the client trusts.
3. Ask the client to run `subsoil verify evidence.jsonl` (or the Python snippet)
   before reading the findings.
4. Keep the original files; hashes in a report prove nothing if the log is lost.

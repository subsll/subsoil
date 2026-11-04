# Contributing

Thanks for taking a look at Subsoil. Bug reports, documentation fixes and pull
requests are welcome.

## Requirements

- Go 1.25 or newer
- `make` (optional, but convenient)

## Development

```sh
make test      # go test ./...
make race      # go test -race ./...
make vet       # go vet ./...
make fmt       # gofmt -w .
make build     # dist/subsoil
```

The test suite is self-contained: it starts an in-process authoritative DNS
server, mock HTTP servers and fixture passive sources. No internet access is
required.

## Guidelines

- Keep the code `gofmt`-clean and `go vet`-clean.
- Add or update tests for behaviour changes. The evidence format is
  security-sensitive: changing the canonical JSON or hashing rules requires
  updating `docs/evidence.md` and the verifier tests.
- Avoid new dependencies unless they are clearly justified. The binary is
  deliberately small and dependency-light.
- Preserve the evidence-chain compatibility guarantees described in
  `docs/evidence.md`.
- Do not add features that harvest personal data, scrape search engines, or
  query breach databases.

## Module path

The module path is `github.com/subsll/subsoil`, matching the repository URL so
that `go install github.com/subsll/subsoil/cmd/subsoil@latest` works. If you
publish a fork under another URL, rename the module and all internal imports,
then update the `-X .../internal/model.Version` linker paths in `Makefile` and
`.github/workflows/release.yml`.

## Releasing

1. Update `CHANGELOG.md` and `VERSION` in the `Makefile`.
2. Run `make test`, `make race`, `make vet` and `make linux`.
3. Commit, tag `vX.Y.Z`, and push the tag:

   ```sh
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

4. The release workflow builds static Linux binaries for amd64, arm64, armv7 and
   386, generates `SHA256SUMS`, and attaches everything to the GitHub release.
   The repository must allow workflow write access: Settings → Actions → General
   → Workflow permissions → Read and write permissions.
5. Verify the uploaded assets and checksums before announcing the release.

## Security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

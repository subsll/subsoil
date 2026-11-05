# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.4.x | yes |
| < 1.4 | no |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include the Subsoil version, operating system, the command used, and enough
   detail to reproduce the issue.

Do not open a public issue for a security problem. Please allow time for a fix
and a coordinated release before disclosure.

Maintainers: enable **Private vulnerability reporting** in the repository's
Settings → Code security so this route is available.

## Scope

In scope:

- CLI argument handling and path traversal in wordlist/report handling
- Evidence-chain integrity or verifier bypasses
- Crashes or resource exhaustion triggered by network responses
- Unsafe HTML/Markdown report rendering
- Release artefact or checksum issues

Out of scope:

- Accuracy or completeness of third-party passive sources
- DNS results for targets you are not authorised to test
- Rate limiting or blocking by public resolvers or passive providers
- Findings produced by scanning systems without permission

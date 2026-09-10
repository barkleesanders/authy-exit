# Validation and observed scope

Version 0.1.0 was developed on macOS arm64 on September 10, 2026.

Local release checks passed: Go tests with the race detector, `go vet`, a trimmed
build, Python capture tests, and `govulncheck` with no reported vulnerabilities.
Gitleaks passed with only the public RFC 6238 test secret explicitly allowlisted.
An exact-value sweep of source files found no owner password, TOTP seed, captured
ciphertext, phone ID, private account email or local home path.

## Automated evidence

- Go tests exercise RFC 6238 SHA-1 vectors, AES-CBC decryption, incorrect passwords,
  malformed IV/ciphertext/KDF parameters, noncanonical and weak Base32 seeds.
- Metadata tests prove theme fields do not become usernames, logos survive the
  join, and uncaptured inventory accounts remain visible.
- Backup tests exercise a synthetic SQLite manifest and binary preferences plist,
  including a whitelist check that unrelated secrets are not extracted.
- Export tests cover complete-or-fail behavior, explicit exclusions, capture digest
  binding, review requirements, owner-only output and overwrite/symlink refusal.
- Vault tests exercise preservation of passwords/passkeys/notes/custom fields,
  explicit identity checks, conflicting seeds, changed targets, preview-only
  behavior and idempotent retry of both creates and attachments.
- Capture tests exercise host/device filtering, whitelist persistence, metadata
  merging, changed encryption envelopes and symlink refusal.
- CLI tests walk every command's help, reject a password argument and check that
  failed/unreviewed exports create no output file.
- An isolated capture launcher smoke test started the installed mitmproxy with a
  dedicated CA directory and confirmed an unconfigured client produced no capture.
  It used a separate port and did not change the owner's active phone proxy.

## Private real-input validation

The new Go inventory command read the owner's original backup and recovered all
65 account records. A capture contained 62 encrypted standard token records;
three inventory entries had no captured portable seed. After applying the owner's
seven exclusions, the new exporter produced 55 retained tokens. Every exported
seed matched the earlier validated migration output. No private input or output
is distributed with this project.

This verifies the observed encryption and inventory formats against real input.
It does not establish compatibility with every Authy release, prove every service
still accepts a given enrollment, or certify the newly written Bitwarden apply
command against every live server. Apply is tested with a synthetic vault and
the installed official `bw create/edit` stdin contract was inspected directly.

## Climaker / CLI Printing Press

Ran the supported hand-built CLI audit commands using CLI Printing Press 4.30.2.
The initial dogfood verdict was WARN: OpenAPI/auth checks were skipped, and the
press did not recognize this project's command-directory layout or expected
SQLite sync/search pipeline. The initial generic scorecard was 55/C before the
README was added; its REST/cache/MCP dimensions are not a migration certification.

No OpenAPI spec was invented and no Grade-A claim is made. The runnable tests and
real-input validation above are the domain-specific evidence for this tool.

## Operational boundaries

The proxy launcher needs owner-managed iPhone settings. No device trust or CA
installation is automated. The addon does not rewrite requests or bypass pinning.
Bitwarden apply is sequential and recoverable by private receipt, not atomic.
Stop concurrent vault editing during a run. Keep Authy available until codes and
service sign-ins have been verified. Unsupported managed or malformed tokens need
explicit re-enrollment rather than guessed secrets.

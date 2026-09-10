# authy-exit

Move your own Authy TOTP accounts into Bitwarden using a local iPhone capture,
your Authy backup password, and reviewed account metadata.

This is an independent, experimental migration tool. It does not contact Authy
support, recover forgotten passwords, or guarantee that every Authy account can
be exported. The supported capture format was observed in an owner-authorized
iPhone migration on September 10, 2026. App and service changes can break it.

**Start with the illustrated [iPhone setup guide](docs/iphone-transfer.html).**
It covers the cable connection, Wi-Fi proxy, certificate installation, full trust,
capture, backup metadata, account review, Bitwarden automation, and cleanup.
The [printable PDF guide](docs/iphone-transfer.pdf) opens directly on GitHub.

## What it automates

| Step | Tool behavior | Owner action |
|---|---|---|
| Capture | Launch mitmproxy; accept the specified phone; save only allowed encrypted token fields | Configure iPhone Wi-Fi proxy and trust the local certificate |
| Inventory | Locate Authy group preferences through the backup manifest; extract account labels and logos | Connect/unlock iPhone and create a readable local backup |
| Plan | Join records by token ID; flag missing seeds and duplicate labels | Confirm names, usernames and websites; explicitly exclude unsupported entries |
| Export | Decrypt locally and produce a Bitwarden JSON file | Enter the Authy backup password in a hidden prompt |
| Verify | Compare a phone code against local TOTP generation without displaying the seed | Read the current code from the correct Authy account |
| Apply | Attach to explicit Bitwarden item IDs; create unmatched entries; verify readback | Unlock Bitwarden and review the preview before adding `--yes` |

USB carries the backup. Wi-Fi carries the proxied Authy traffic. Connecting a USB
cable alone does not route Authy through the proxy.

## Build

Requires Go 1.26.4 or newer. The Go core builds on macOS and Linux; the documented
device walkthrough targets iPhone + macOS. Python 3 and mitmproxy are needed only
for capture. Bitwarden's `bw` CLI is needed only for `apply`.

```sh
git clone https://github.com/barkleesanders/authy-exit.git
cd authy-exit
go build -trimpath -o bin/authy-exit ./cmd/authy-exit
./bin/authy-exit doctor
```

On a Mac with Homebrew, install the optional tools you intend to use:

```sh
brew install mitmproxy libimobiledevice bitwarden-cli
```

The executable is referred to as `./bin/authy-exit` below. Run commands from the
repository directory. Use a new private working directory outside cloud-synced
Downloads, Desktop or Documents folders:

```sh
umask 077
WORK="$HOME/.local/share/authy-exit/session-1"
mkdir -p "$WORK"
chmod 700 "$WORK"
```

## Capture from your own iPhone

Put your computer and iPhone on the same trusted Wi-Fi network. Find each device's
local IP address. The addresses below are examples: replace both with yours.

```sh
./bin/authy-exit capture \
  --listen 192.168.50.10 --phone 192.168.50.20 --port 8088 \
  --dir "$WORK" --addon ./capture/mitm_authy.py
```

Keep this terminal open. On iPhone, open Settings → Wi-Fi → your network's ⓘ →
Configure Proxy → Manual. Enter the computer's IP, port `8088`, and leave
authentication off. Visit `http://mitm.it` in Safari, install the generated
certificate profile, then enable its full trust under Settings → General → About
→ Certificate Trust Settings. [Apple documents the separate full-trust step](https://support.apple.com/en-us/102390).

Open Authy and let it sync. Backups must already be enabled and the standard
accounts unlocked. A normal app reopen or saving a harmless account-label edit
may produce a token sync, depending on the app version. Restore any edited label
afterward. This tool does not force synchronization by modifying network requests.
Do not delete accounts, reset Authy, or disable backups to provoke traffic.

The addon writes `captured-encrypted-tokens.json` and merges subsequent captured
records by token ID. It does not save raw HARs, request headers, cookies or API
authentication tokens. Other HTTPS hosts pass through without TLS interception;
ordinary HTTP still traverses the proxy but is not persisted by this addon.
The proxy uses its own configuration and CA directory at `$WORK/mitmproxy`,
so an existing global mitmproxy configuration cannot enable extra capture logging.

**Turn off the iPhone's proxy before stopping the capture process.** If migration
needs more capture, keep both configured and the computer awake. A configured
proxy with no running listener breaks the phone's Wi-Fi traffic.

## Recover labels and logos

Connect the iPhone by cable, unlock it, and approve Trust on both devices. Create
a backup using Finder, or select your own device with libimobiledevice:

```sh
idevice_id -l
idevicepair -u YOUR_DEVICE_UDID pair
idevicebackup2 -u YOUR_DEVICE_UDID -i backup --full "$WORK/backup"
```

The backup contains sensitive data from the phone. Use a private directory and
adequate free disk space. `inventory` needs a readable `Manifest.db` and readable
Authy preferences. It does not decrypt encrypted Finder backups. If your backup
is encrypted, extract the group preferences locally with a trusted backup tool
and your backup password, then use `--plist` instead. You may also omit inventory
and review the less complete capture metadata manually.

```sh
./bin/authy-exit inventory \
  --backup "$WORK/backup/YOUR_DEVICE_UDID" \
  --out "$WORK/inventory.json"

./bin/authy-exit plan \
  --capture "$WORK/captured-encrypted-tokens.json" \
  --inventory "$WORK/inventory.json" \
  --out "$WORK/plan.json"
```

Open `plan.json` locally. For each entry, confirm `name`, `issuer`, `username` and
`urls`, then set `reviewed` to `true`. Use `exclude: true` for accounts you do not
want or whose seed is unavailable. Leave an unknown username empty. Only add a
website after checking the service; never paste a secret-bearing `otpauth` URI
into `urls`. Website URLs must be HTTPS without credentials, queries or fragments.

The plan displays the original logo and explicitly labels the theme as
`theme_not_username`. **`Generic Blue` and `authenticator` are icon/theme values,
not login usernames.** Labels such as `Service:account` supply a candidate account
identifier, but that suffix can be an internal ID. A logo helps identify a service;
it does not establish which of several logins owns a token.

Duplicate labels retain distinct token IDs. Never collapse them just because
their names match. The plan is tied to the capture's SHA-256 digest; if capture
changes, make and review a new plan.

## Decrypt and verify

```sh
./bin/authy-exit export \
  --capture "$WORK/captured-encrypted-tokens.json" \
  --plan "$WORK/plan.json" --dry-run

./bin/authy-exit export \
  --capture "$WORK/captured-encrypted-tokens.json" \
  --plan "$WORK/plan.json" --out "$WORK/bitwarden.json"

./bin/authy-exit verify \
  --capture "$WORK/captured-encrypted-tokens.json" \
  --plan "$WORK/plan.json" --id YOUR_TOKEN_ID
```

The password is the **Authy encrypted-backup password**, not the iPhone passcode,
Finder-backup password, or Bitwarden master password. The tool prompts without
echo. Automation can use `--password-stdin --no-input` with a secret manager piping
the password directly; there is deliberately no password argument or environment
variable option. Never put a real password in an `echo` command or a script.

`export --dry-run` really decrypts and validates all included tokens, without
writing an export. Any invalid included record fails the entire export. `verify`
accepts the current or adjacent 30-second window. Repeat after the code changes,
then test a real service login before retiring its Authy entry. Local code
agreement alone does not prove the service still accepts that enrollment.

Output files use mode `0600`, require a private parent directory, and refuse to
overwrite an existing file or symlink. The import file **contains plaintext TOTP
secrets**. The program prints aggregate results, never the seeds or generated codes.

## Apply to Bitwarden

Sign in with the official Bitwarden CLI and unlock it. Check `bw status` to obtain
the exact user email and server URL. Keep the session key in your current shell:

```sh
bw login
export BW_SESSION="$(bw unlock --raw)"
bw status
```

Create a private `targets.json` object mapping source token IDs from `plan.json`
to existing Bitwarden login item IDs. Use the vault's item details or the official
CLI locally to identify the correct item. An empty object `{}` creates standalone
entries for every included source. For example (all values synthetic):

```json
{"synthetic-1": "00000000-0000-4000-8000-000000000099"}
```

Preview first. Replace the email and URL with your exact `bw status` values:

```sh
./bin/authy-exit apply \
  --file "$WORK/bitwarden.json" --targets "$WORK/targets.json" \
  --expected-user you@example.invalid \
  --expected-server https://vault.bitwarden.com
```

Apply the reviewed preview with `--yes` and a new private receipt filename:

```sh
./bin/authy-exit apply \
  --file "$WORK/bitwarden.json" --targets "$WORK/targets.json" \
  --expected-user you@example.invalid \
  --expected-server https://vault.bitwarden.com \
  --receipt "$WORK/apply-receipt-1.json" --yes

bw lock
unset BW_SESSION
```

The apply step checks vault identity, syncs, validates every planned operation,
and saves original target items before writing. Existing passwords, usernames,
passkeys, URLs, notes and other fields are preserved; the code, a migration marker,
and the Verification codes folder assignment are added. A different existing TOTP
blocks the run. Multiple sources cannot target one login. Each write is read back.

Retries recognize source markers and matching codes. The operation is **not a
transaction**: a network failure can leave earlier writes completed. Keep the
receipt, run the preview again, and use a new receipt filename for remaining work.
Do not edit the same vault items from another device while applying: the CLI
checks for changes but cannot guarantee a server-side compare-and-swap.

The rollback receipt also contains secrets, including original passwords for
attached targets. It is a recovery artifact, not something to upload to an issue.
To reverse an attachment, use the receipt's `before` item locally with `bw edit`
through stdin. Review each reversal; do not bulk-reimport the receipt.

Alternatively, import `bitwarden.json` through Bitwarden's UI using the Bitwarden
JSON format. **UI import creates items; it does not attach them to existing
logins. Choose the UI import or `apply`, not both.**

## Limits and security

- Supported envelope: PBKDF2-HMAC-SHA1, 32-byte key, AES-256-CBC, strict PKCS#7;
  per-record iterations from 1 to 1,000,000; hexadecimal IV or legacy zero IV.
- Supported tokens: canonical Base32 seeds of at least 10 bytes, SHA-1 TOTP,
  30-second period, 6 or 8 digits. Noncanonical/very weak seeds are rejected.
- Authy-managed tokens whose sync response omits their seed cannot be migrated
  by this tool. Re-enroll those services using their account security settings.
- No key recovery, account takeover, device registration automation, request
  rewriting, certificate-pinning bypass, telemetry, or plaintext secret database.
- Capture is version-dependent. A valid certificate does not guarantee the app
  will accept interception. If it rejects the connection, stop and use service
  re-enrollment or another legitimate export route.
- AES-CBC here is an observed legacy format without an authentication tag.
  Padding and Base32 checks detect many mistakes but cannot authenticate a
  maliciously modified capture. Keep originals private and compare phone codes.
- Memory clearing is best effort; Go strings/runtime copies cannot be guaranteed
  erased. Disk snapshots, swap and cloud backup can retain deleted exports.

After successful service checks, turn off the iPhone proxy, stop the listener,
disable trust for the temporary certificate, and remove its profile. Decide
locally which encrypted backups/receipts to retain. Never publish capture files,
phone backups, exports, session keys, passwords or account metadata.

## Development and validation

```sh
go test -race ./...
go vet ./...
python3 -m unittest discover -s capture -v
go build -trimpath -o bin/authy-exit ./cmd/authy-exit
```

Tests use synthetic accounts and the public RFC 6238 SHA-1 test vector. They cover
decryption failures, metadata identity, backup manifest selection, private output,
vault identity checks, preservation, source-marker retries and write conflicts.

The core was also validated locally against the owner's capture and iPhone backup;
private files are not included. The new `apply` implementation has automated
synthetic-vault tests, not a production write certification across all Bitwarden
versions. See [validation notes](docs/validation.md).

Requested through **climaker**. Its supported hand-built CLI audit commands were
run using [CLI Printing Press](https://github.com/mvanhorn/cli-printing-press).
This project is a local migration pipeline, not a generated REST API wrapper:
the press's OpenAPI/cache/MCP scoring dimensions mostly do not apply. We report
those skips rather than claiming a generated Grade-A CLI or inventing an Authy API.

## Sources and credits

- [Apple: cable connection, trust and Finder backups](https://support.apple.com/en-us/108796).
- [Apple: manually trust certificate profiles](https://support.apple.com/en-us/102390).
- [mitmproxy: certificates](https://docs.mitmproxy.org/stable/concepts/certificates/) and [ignored domains](https://docs.mitmproxy.org/stable/howto/ignore-domains/).
- [libimobiledevice: backup command](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1).
- [Bitwarden: custom JSON imports](https://bitwarden.com/help/condition-bitwarden-import/) and [official CLI](https://bitwarden.com/help/cli/).
- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238): TOTP and public test vectors.
- [uiltondutra/authy-migrate](https://github.com/uiltondutra/authy-migrate): prior art
  for decrypting an Authy data-request export; consulted for the legacy encryption
  format. This project independently implements capture, metadata review and
  Bitwarden migration in Go. It does not bundle proprietary Authy code or assets.

MIT licensed. Authy, Twilio and Bitwarden are names of their respective products;
this project is not affiliated with or endorsed by them.

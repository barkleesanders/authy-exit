# Security

This tool handles authenticator seeds and can modify a Bitwarden vault. Test with
synthetic accounts first. Use it only with devices and accounts you own or are
authorized to administer.

Never attach real captures, backup preferences, QR codes, TOTP URIs, export files,
rollback receipts, vault session keys or passwords to public issues. A useful
report contains the tool version, command name, sanitized error category and a
synthetic reproduction. Do not include a full terminal transcript.

Core migration is offline. The optional capture proxy contacts the services your
phone requests; the optional apply command invokes your installed Bitwarden CLI.
Pin and review dependencies appropriate to your environment. Do not run another
person's capture addon or trust another person's root certificate.

The temporary CA private key, encrypted capture and all plaintext outputs need
protection. File modes are a Unix safeguard, not protection from the same user,
malware, administrator access, disk snapshots, or cloud synchronization. Private
work directories must not be inside a synchronized folder.

See the README for format limits, nontransactional apply behavior and cleanup.
Until a private disclosure channel is established, do not post exploit details
that expose a live account. Share only a secret-free synthetic reproduction.

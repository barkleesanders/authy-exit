# Contributing

Use Go formatting and run the commands in the README's validation section.
Add synthetic regression tests when changing crypto parsing, account identity,
capture filtering, or vault writes. Include an end-to-end command example when
adding a command. Never use real account data in fixtures, screenshots or logs.

Keep token IDs distinct. Do not replace uncertainty with guessed websites or
usernames. Do not broaden captured fields without documenting why each is needed.
Do not add password arguments, secret stdout, automatic backup disabling, or
silent TOTP overwrites. New formats must be explicit and tested against public or
synthetic vectors. Proprietary application code and assets must not be bundled.

The project is intentionally small: capture → inventory → review → export →
verify → apply. Changes should keep that workflow inspectable and preserve owner
control over device trust and live vault writes.

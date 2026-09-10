"""Opt-in capture for one owner's iPhone. Never persist headers or raw flows."""

import ipaddress
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIELDS = frozenset({
    "unique_id", "token_id", "id", "encrypted_seed", "salt", "unique_iv",
    "key_derivation_iterations", "digits", "name", "original_name", "issuer",
    "username", "logo", "account_type", "algorithm", "period",
})


def tokens_in(value, depth=0):
    if depth > 20:
        return
    if isinstance(value, list):
        for item in value:
            yield from tokens_in(item, depth + 1)
    elif isinstance(value, dict):
        token_id = value.get("unique_id") or value.get("token_id") or value.get("id")
        if token_id is not None and value.get("encrypted_seed") and value.get("salt"):
            record = {k: v for k, v in value.items()
                      if k in FIELDS and isinstance(v, (str, int)) and not isinstance(v, bool)}
            record["unique_id"] = str(token_id)
            yield record
        else:
            for child in value.values():
                yield from tokens_in(child, depth + 1)


class Capture:
    def __init__(self, directory=None, phone=None):
        self.directory = Path(directory or os.environ["AUTHY_EXIT_DIR"])
        self.phone = str(ipaddress.ip_address(phone or os.environ["AUTHY_EXIT_PHONE"]))
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.stat().st_mode & 0o077:
            raise ValueError("capture directory must have mode 700")
        self.path = self.directory / "captured-encrypted-tokens.json"
        if self.path.is_symlink():
            raise ValueError("capture destination must not be a symlink")
        self.records = {}
        if self.path.exists():
            if self.path.stat().st_size > 32 * 1024 * 1024:
                raise ValueError("capture exceeds size limit")
            old = json.loads(self.path.read_text())
            for record in tokens_in(old):
                self.records[record["unique_id"]] = record

    def eligible(self, flow):
        peer = getattr(flow.client_conn, "peername", None)
        return (peer and peer[0] == self.phone
                and flow.request.host == "api.authy.com"
                and "authenticator_tokens" in urlsplit(flow.request.path).path.split("/"))

    def client_connected(self, client):
        peer = getattr(client, "peername", None)
        if not peer or peer[0] != self.phone:
            client.error = "This capture is restricted to the configured device."

    def save(self, value):
        changed = False
        for record in tokens_in(value):
            key = record["unique_id"]
            old = self.records.get(key, {})
            # A new ciphertext must not inherit an IV/KDF from an older envelope.
            if old.get("encrypted_seed") not in (None, record.get("encrypted_seed")):
                old = {k: v for k, v in old.items()
                       if k not in {"encrypted_seed", "salt", "unique_iv", "key_derivation_iterations"}}
            merged = {**old, **record}
            if merged != self.records.get(key):
                self.records[key] = merged
                changed = True
        if len(self.records) > 1000:
            raise ValueError("capture exceeds token limit")
        if not changed:
            return
        fd, temporary = tempfile.mkstemp(prefix=".capture-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump({"authenticator_tokens": list(self.records.values())}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def request(self, flow):
        if not self.eligible(flow) or flow.request.method != "POST":
            return
        body = flow.request.get_text(strict=False)
        if not body or len(body) > 32 * 1024 * 1024:
            return
        try:
            value = json.loads(body)
        except (ValueError, RecursionError):
            value = {k: v[-1] for k, v in parse_qs(body).items()}
        self.save(value)

    def response(self, flow):
        if not self.eligible(flow) or not flow.response or flow.response.status_code != 200:
            return
        if len(flow.response.content or b"") > 32 * 1024 * 1024:
            return
        try:
            value = flow.response.json()
        except (ValueError, RecursionError):
            return
        self.save(value)


addons = [Capture()] if "AUTHY_EXIT_DIR" in os.environ else []

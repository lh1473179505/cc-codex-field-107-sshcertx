from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import time
from typing import Any

_KIND = "sshcertx"

# Stable snake_case reason codes, one per admission gate.
CA_UNKNOWN = "ca_unknown"
CA_REVOKED = "ca_revoked"
BAD_SIGNATURE = "bad_signature"
PRINCIPAL_DENIED = "principal_denied"
FORCE_COMMAND_DENIED = "force_command_denied"
SOURCE_REQUIRED = "source_required"
SOURCE_DENIED = "source_denied"
NOT_YET_VALID = "not_yet_valid"
EXPIRED = "expired"
SERIAL_REPLAY = "serial_replay"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hmac_b64url(secret_hex: str, line: str) -> str:
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _principals(obj: dict) -> list[str]:
    principals = obj.get("principals")
    if isinstance(principals, list):
        return [str(p) for p in principals]
    if isinstance(principals, str) and principals:
        return principals.split(",")
    return []


def signing_input(obj: dict) -> str:
    """Rebuild the v1 signing line from the certificate itself.

    A supplied ``_sign_line`` is an untrusted hint and is never relied upon.
    """
    ca_kid = obj.get("ca_kid") or obj.get("kid")
    valid_after = obj.get("valid_after")
    valid_before = obj.get("valid_before")
    return "v1|{ca_kid}|{key_id}|{principals}|{force_command}|{source_address}|{valid_after}|{valid_before}".format(
        ca_kid=ca_kid if ca_kid is not None else "",
        key_id=obj.get("key_id") or "",
        principals=",".join(_principals(obj)),
        force_command=obj.get("force_command") or "",
        source_address=obj.get("source_address") or "",
        valid_after="" if valid_after is None else valid_after,
        valid_before="" if valid_before is None else valid_before,
    )


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "sshcertx", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a certificate against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The serial is
    recorded in ``store`` only when the decision is allow; a deny never
    mutates the store.
    """
    if now_unix is None:
        now_unix = int(time.time())
    report = {"decision": "deny", "reason_codes": [], "kind": _KIND, "notes": []}
    reasons = report["reason_codes"]

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    # Gate 1: the CA kid must exist and be active. A revoked kid denies
    # even when the HMAC itself verifies.
    ca_kid = obj.get("ca_kid") or obj.get("kid")
    entry = _keyring(keys).get(ca_kid)
    active_entry = entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    if entry is None:
        add(CA_UNKNOWN)
    elif active_entry is None:
        add(CA_REVOKED)

    # Gate 2: recompute the v1 signing line from the certificate and
    # verify the HMAC.
    if active_entry is not None:
        expected = _hmac_b64url(active_entry["secret"], signing_input(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            add(BAD_SIGNATURE)

    # Gate 3: principals must intersect policy.allowed_principals.
    allowed_principals = set(policy.get("allowed_principals") or [])
    if not any(p in allowed_principals for p in _principals(obj)):
        add(PRINCIPAL_DENIED)

    # Gate 4: force-command must exactly hit the allow table, or be empty
    # with policy.allow_interactive.
    force_command = obj.get("force_command") or ""
    if force_command:
        if force_command not in (policy.get("allowed_force_commands") or []):
            add(FORCE_COMMAND_DENIED)
    elif not policy.get("allow_interactive"):
        add(FORCE_COMMAND_DENIED)

    # Gate 5: the source-address CIDR must cover the connection source; a
    # missing connection source denies with source_required.
    client = obj.get("client_address") or obj.get("connection_source")
    if not client:
        add(SOURCE_REQUIRED)
    else:
        cidr = obj.get("source_address") or ""
        if cidr:
            try:
                network = ipaddress.ip_network(str(cidr), strict=False)
                address = ipaddress.ip_address(str(client))
                if address not in network:
                    add(SOURCE_DENIED)
            except ValueError:
                add(SOURCE_DENIED)

    # Gate 6: valid_after/valid_before bound now, with clock skew.
    skew = policy.get("clock_skew_seconds", 60)
    valid_after = obj.get("valid_after")
    valid_before = obj.get("valid_before")
    if isinstance(valid_after, int) and now_unix < valid_after - skew:
        add(NOT_YET_VALID)
    if isinstance(valid_before, int) and now_unix > valid_before + skew:
        add(EXPIRED)

    # Gate 7: replay protection. A serial may be consumed only once, and
    # only an allow may record it.
    serial = obj.get("serial") or obj.get("id")
    items = store.get("items") if isinstance(store, dict) else None
    if serial is not None and isinstance(items, dict) and serial in items:
        add(SERIAL_REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    if serial is not None:
        store.setdefault("items", {})[serial] = {"ts": int(now_unix)}
    return report

"""Nano (XNO) proofs checked against the operator's own Nano node, opt-in.

A port of ``src/nano.js`` and ``src/nano-claims-file.js`` from
@profullstack/x402-gateway, the "XNO checked by your own node" mode.

A Nano block has no memo, so a confirmed send proves money reached an account
and says nothing about which sale it paid for, and its hash is public, so
anyone who reads the ledger can present it. Two checks close that, following
the xno-binding v1 order commitment
(https://github.com/dhyabi2/xno-call-binding/blob/main/docs/BINDING-STANDARD.md,
option C):

- Bound to the order. The payer picks a random order id and signs its send
  with ``representative`` set to SHA-256("xno-binding/v1/rep|" + orderId +
  "|" + payTo + "|" + amountRaw), encoded as a ``nano_`` account. The gateway
  recomputes that from the order id in the proof and the offered payee and
  amount, so a block only proves the order it was signed for.
- Single-use, across restarts. A verified block is claimed in a store the
  operator supplies (block hash and order id, each at most once).
  :class:`FileClaims` appends and fsyncs every claim and reads them back on
  start.

No key, no seed, no signing: the node is only read (``block_info``). Amounts
are integer raw (1 XNO = 10**30 raw) and must match exactly. Addresses are
checksum-validated. Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import secrets
import threading
from typing import Any, Callable, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

#: Raw per XNO. Every amount here is an integer number of raw.
RAW_PER_XNO = 10**30

# ------------------------------------------------------------- accounts --

_ALPHABET = "13456789abcdefghijkmnopqrstuwxyz"
_ACCOUNT = re.compile(r"^(nano|xrb)_([13][13456789abcdefghijkmnopqrstuwxyz]{59})$")


def _encode32(value: int, chars: int) -> str:
    return "".join(_ALPHABET[(value >> (5 * i)) & 31] for i in range(chars - 1, -1, -1))


def _decode32(text: str) -> int:
    v = 0
    for ch in text:
        v = (v << 5) | _ALPHABET.index(ch)
    return v


def _checksum(key: bytes) -> bytes:
    """The 5-byte checksum of a public key, in the order the address writes it."""
    return hashlib.blake2b(key, digest_size=5).digest()[::-1]


def account_from_key(key: bytes) -> str:
    """A 32-byte public key (or any 32 bytes) as a ``nano_`` account."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("an account is 32 bytes")
    key = bytes(key)
    return "nano_" + _encode32(int.from_bytes(key, "big"), 52) + _encode32(int.from_bytes(_checksum(key), "big"), 8)


def account_key(address: Any) -> Optional[bytes]:
    """The 32-byte public key of a ``nano_`` or ``xrb_`` account, or None if the
    text is not one or its checksum does not match. A mistyped address that
    still fits the alphabet fails here rather than taking payments for an
    account nobody holds."""
    m = _ACCOUNT.match(str(address if address is not None else "").strip().lower())
    if not m:
        return None
    k = _decode32(m.group(2)[:52])
    if k >> 256:
        return None
    key = k.to_bytes(32, "big")
    return key if int.from_bytes(_checksum(key), "big") == _decode32(m.group(2)[52:]) else None


def canonical_account(address: Any) -> Optional[str]:
    """A checksum-valid account in canonical ``nano_`` form, or None."""
    key = account_key(address)
    return account_from_key(key) if key is not None else None


def nano_payee(address: Any) -> Optional[str]:
    """A Nano payee in canonical ``nano_`` form, or None if it is not one."""
    return canonical_account(address)


def xno_raw(price_cents: Any, rate: Any) -> Optional[str]:
    """A price in raw XNO, rounded UP, at ``rate`` units of the price's currency
    per XNO. Integer arithmetic throughout: the rate is read to 10**-9 and the
    price to 10**-6 of a cent, as the reference does. None if either is not a
    positive number."""

    def js_round(x: Any, scale: float) -> int:
        if isinstance(x, bool):
            return 0
        try:
            f = float(x) * scale
        except (TypeError, ValueError):
            return 0
        return int(math.floor(f + 0.5)) if math.isfinite(f) else 0

    cents = js_round(price_cents, 1e6)
    per = js_round(rate, 1e9)
    if cents <= 0 or per <= 0:
        return None
    # raw = (cents / 100) / rate * 10^30 = (cents*1e6) * 10^31 / (rate*1e9)
    num = cents * 10**31
    return str((num + per - 1) // per)


# -------------------------------------------------------------- binding --

BINDING = "xno-binding/v1/rep"
_ORDER_ID = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_RAW = re.compile(r"^[1-9][0-9]*$")


def new_order_id() -> str:
    """A fresh random order id: 16 bytes, base64url, 22 characters."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def is_order_id(order_id: Any) -> bool:
    """Whether an order id is long and plain enough to be a secret the payer chose at random."""
    return isinstance(order_id, str) and _ORDER_ID.fullmatch(order_id) is not None


def order_commitment(order_id: str, pay_to: str, amount: str) -> bytes:
    """SHA-256("xno-binding/v1/rep|" + orderId + "|" + payTo + "|" + amountRaw), as 32 bytes."""
    return hashlib.sha256(f"{BINDING}|{order_id}|{pay_to}|{amount}".encode("utf-8")).digest()


def order_representative(order_id: str, pay_to: str, amount: str) -> str:
    """The representative a payer sets on its send to bind it to this order."""
    return account_from_key(order_commitment(order_id, pay_to, amount))


# ------------------------------------------------------------- the node --

_LOOPBACK = re.compile(r"^(localhost|127(?:\.\d{1,3}){3}|::1)$", re.I)


def node_url(url: Any) -> Optional[str]:
    """The node URL if it is one the gateway will read money from: https, or
    plain http only on loopback (a node beside the gateway). None otherwise."""
    try:
        u = urlsplit(str(url if url is not None else "").strip())
        host = u.hostname or ""
        u.port  # noqa: B018 - raises on a malformed port
    except ValueError:
        return None
    if not host:
        return None
    if u.scheme == "https" or (u.scheme == "http" and _LOOPBACK.match(host)):
        return urlunsplit((u.scheme, u.netloc, u.path or "/", u.query, ""))
    return None


_MAX_BODY = 64 * 1024

#: ``post(url, headers, body_text) -> (status, body_text)``, the gateway's own poster.
Poster = Callable[[str, Mapping[str, str], str], Tuple[int, str]]


def read_block(block_hash: str, rpc_url: str, post: Poster) -> Dict[str, Any]:
    """One block as the node reports it, or ``{"error": ...}``. The answer is
    size-capped, since the node is outside the gateway."""
    body = json.dumps({"action": "block_info", "json_block": "true", "hash": block_hash})
    try:
        _, text = post(rpc_url, {"content-type": "application/json"}, body)
    except Exception as e:  # noqa: BLE001 - any transport failure is "did not answer"
        return {"error": f"the Nano node did not answer ({type(e).__name__})"}
    text = str(text if text is not None else "")
    if len(text) > _MAX_BODY:
        return {"error": "the Nano node answer is too large"}
    try:
        info = json.loads(text)
    except ValueError:
        return {"error": "the Nano node answer is not JSON"}
    if not isinstance(info, dict) or info.get("error") or not isinstance(info.get("contents"), dict):
        detail = f" ({info.get('error')})" if isinstance(info, dict) and info.get("error") else ""
        return {"error": f"the Nano node does not know this block{detail}"}
    c = info["contents"]
    confirmed = info.get("confirmed")
    return {
        "account": canonical_account(info.get("block_account") or c.get("account")),
        "to": canonical_account(c.get("link_as_account")),
        "representative": canonical_account(c.get("representative")),
        "amount": str(info.get("amount") if info.get("amount") is not None else ""),
        "subtype": str(info.get("subtype") or ""),
        "type": str(c.get("type") or ""),
        "confirmed": confirmed is True or confirmed == "true",
    }


# --------------------------------------------------------------- claims --


class MemoryClaims:
    """Claims in memory. For tests and for trying the flow out only: a restart
    forgets every claim, and every block it forgot can be presented again.
    Production uses :class:`FileClaims`, or any object with the same
    ``claim`` method backed by a table with both columns UNIQUE."""

    def __init__(self) -> None:
        self._by_hash: Dict[str, Tuple[str, int]] = {}
        self._by_order: Dict[str, str] = {}
        self._lock = threading.Lock()

    def _held(self, block_hash: str, order_id: str) -> Optional[Dict[str, Any]]:
        held = self._by_hash.get(block_hash)
        if held:
            return {"status": "same", "at": held[1]} if held[0] == order_id else {"status": "taken"}
        if order_id in self._by_order:
            return {"status": "taken"}
        return None

    def _keep(self, block_hash: str, order_id: str, at: int) -> None:
        self._by_hash[block_hash] = (order_id, at)
        self._by_order[order_id] = block_hash

    def claim(self, block_hash: str, order_id: str, at: int) -> Dict[str, Any]:
        with self._lock:
            held = self._held(block_hash, order_id)
            if held:
                return held
            self._keep(block_hash, order_id, int(at))
            return {"status": "new", "at": int(at)}

    def __len__(self) -> int:
        return len(self._by_hash)


_LINE = re.compile(r"^([0-9A-F]{64}) ([A-Za-z0-9_-]{22,128}) (\d+)$")


class FileClaims(MemoryClaims):
    """Nano claims kept in a file, so a restart does not make old blocks
    spendable again.

    One line per claim, ``<BLOCK HASH> <order id> <unix seconds>``, appended
    and fsynced before the claim is reported as new, and read back on start.
    A torn last line from a crash mid-write is skipped. One process per file:
    the check-then-append is atomic inside this process (a lock covers
    threads), not across processes.
    """

    def __init__(self, path: str) -> None:
        if not path:
            raise ValueError("FileClaims needs a path")
        super().__init__()
        self.path = path
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except FileNotFoundError:
            text = ""
        for line in text.split("\n"):
            m = _LINE.match(line.strip())
            if not m or m.group(1) in self._by_hash or m.group(2) in self._by_order:
                continue
            self._keep(m.group(1), m.group(2), int(m.group(3)))

    def claim(self, block_hash: str, order_id: str, at: int) -> Dict[str, Any]:
        with self._lock:
            held = self._held(block_hash, order_id)
            if held:
                return held
            at = int(at)
            line = f"{block_hash} {order_id} {at}"
            if not _LINE.match(line):
                return {"status": "taken"}
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                # A newline first, so a torn line left by a crash cannot swallow this one.
                os.write(fd, f"\n{line}\n".encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            self._keep(block_hash, order_id, at)
            return {"status": "new", "at": at}


# --------------------------------------------------------------- settle --

_HASH = re.compile(r"^[0-9A-F]{64}$")


def _payload(payment: Any) -> Mapping[str, Any]:
    p = payment.get("payload") if isinstance(payment, dict) else None
    return p if isinstance(p, dict) else {}


def settle_nano(
    payment: Any,
    expected: Mapping[str, Any],
    rpc_url: str,
    claims: Any,
    post: Poster,
    now: Callable[[], int],
) -> Dict[str, Any]:
    """Check a Nano proof against the node and claim it.

    ``expected`` is the offered entry's ``{"amount", "payTo"}`` for the days
    the proof pays for. Returns ``{"ok": True, "payer", "ref", "txHash",
    "network"}`` or ``{"ok": False, "reason", "replay"}``, plus ``claimedAt``
    (unix seconds) when the block is already claimed by this same order,
    which is the payer retrying after losing the answer.
    """

    def refuse(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason, "replay": False}

    payload = _payload(payment)
    block_hash = str(payload.get("blockHash") or "").upper()
    if not _HASH.match(block_hash):
        return refuse("A Nano proof needs payload.blockHash, the 64-hex hash of the send block.")
    order_id = payload.get("orderId")
    if not is_order_id(order_id):
        return refuse(
            "A Nano proof needs payload.orderId, the random order id (22 to 128 of A-Z a-z 0-9 _ -) "
            f"the send committed to in its representative ({BINDING})."
        )
    pay_to = canonical_account((expected or {}).get("payTo"))
    amount = str((expected or {}).get("amount") or "")
    if not pay_to or not _RAW.match(amount):
        return refuse("No Nano offer to hold this proof to.")

    block = read_block(block_hash, rpc_url, post)
    if block.get("error"):
        return refuse(block["error"])
    if not block["confirmed"]:
        return refuse("The Nano block is not confirmed yet. Present it again once it is.")
    if block["type"] != "state" or block["subtype"] != "send":
        return refuse("The Nano block is not a send.")
    if block["to"] != pay_to:
        return refuse("The Nano block does not pay this gateway.")
    if block["amount"] != amount:
        return refuse(f"The Nano block sends {block['amount'] or 'nothing'} raw; this offer is exactly {amount} raw.")
    representative = order_representative(order_id, pay_to, amount)
    if block["representative"] != representative:
        return refuse(f"The Nano block is not bound to this order: its representative must be {representative} ({BINDING}).")

    claim = claims.claim(block_hash, order_id, int(now())) or {}
    if claim.get("status") == "new":
        return {"ok": True, "payer": block["account"], "ref": block_hash, "txHash": block_hash, "network": "nano"}
    if claim.get("status") == "same":
        return {"ok": False, "reason": "This Nano block was already used for this order.", "replay": True, "claimedAt": int(claim["at"])}
    return refuse("This Nano block or order id has already been used.")


def normalise_nano(nano: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """The Nano settings, or None when there is no valid payee.

    This port reads Nano proofs from the operator's own node only, so a payee
    comes with ``rpc_url`` and ``claims`` or not at all: reading blocks from
    a node without remembering which ones were credited would sell the same
    block again and again.
    """
    if not nano:
        return None
    pay_to = nano_payee(nano.get("pay_to"))
    if not pay_to:
        return None
    rpc = nano.get("rpc_url")
    if not rpc:
        raise ValueError("nano needs rpc_url: this port checks Nano proofs on your own node (block_info, no key)")
    rpc_url = node_url(rpc)
    if not rpc_url:
        raise ValueError("nano rpc_url must be https, or http on localhost")
    claims = nano.get("claims")
    if not callable(getattr(claims, "claim", None)):
        raise ValueError("nano rpc_url needs nano claims, a store that remembers credited blocks across restarts (x402_gateway.nano.FileClaims)")
    return {"pay_to": pay_to, "rate": nano.get("rate"), "rpc_url": rpc_url, "claims": claims}

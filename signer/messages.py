"""What verify sends, parsed; and the layouts the signer signs itself.

A credential arrives as the exact bytes `ovcrypto.issuer.issue` would sign
(`wire.signed_bytes`), so the signer reads the claims a phone will read --
not a description of them that verify could make say anything.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

from ovcrypto import wire
# The feed's layout is ovcrypto's, the reference both verify and the app are
# held to.
from ovcrypto.feed import (FEED_CONTEXT, FEED_MAGIC, FEED_VERSION,  # noqa: F401
                           feed_signed_bytes)


class MessageError(ValueError):
    pass


@dataclass
class Credential:
    key_id: int
    sig_alg: int
    credential_id: bytes
    issued_at: int
    expires_at: int
    issuer: str            # T_ISSUER_ID, "" if absent
    operator: str          # T_OPERATOR, "" if absent
    document: str          # T_DOC_NUMBER
    location: str
    transaction_type: str


def _text(claims, tag) -> str:
    value = claims.get(tag)
    return value.decode("utf-8", "replace") if value is not None else ""


def parse_credential(message: bytes) -> Credential:
    """Read `wire.signed_bytes` back. Refuses anything else."""
    ctx = wire.SIG_CONTEXT
    if not message.startswith(ctx):
        raise MessageError("not a credential")
    body = message[len(ctx):]
    # version, suite, flags, epoch(4), claims length(2)
    if len(body) < 3 + 4 + 2:
        raise MessageError("truncated")
    flags = body[2]
    (claims_len,) = struct.unpack_from(">H", body, 7)
    claims_end = 9 + claims_len
    if len(body) != claims_end + wire.HASH_LEN + 1 + 4:
        raise MessageError("wrong length")
    claims_bytes = body[9:claims_end]
    sig_alg = body[claims_end + wire.HASH_LEN]
    (key_id,) = struct.unpack_from(">I", body, claims_end + wire.HASH_LEN + 1)
    try:
        if flags & wire.FLAG_PUBLIC_DEFLATED:
            claims_bytes = wire.inflate(claims_bytes)
        claims = wire.decode_claims(claims_bytes)
    except wire.WireError as exc:
        raise MessageError("claims: %s" % exc)
    for tag in claims:
        if tag not in wire.PUBLIC_TAGS:
            raise MessageError("restricted tag in the public claims")
    cid = claims.get(wire.T_CREDENTIAL_ID)
    issued = claims.get(wire.T_ISSUED_AT)
    expires = claims.get(wire.T_EXPIRES_AT)
    if cid is None or len(cid) != 16 or issued is None or expires is None:
        raise MessageError("a credential needs an id, issued_at and expires_at")
    return Credential(
        key_id=key_id, sig_alg=sig_alg, credential_id=bytes(cid),
        issued_at=wire.read_u32(issued), expires_at=wire.read_u32(expires),
        issuer=_text(claims, wire.T_ISSUER_ID),
        operator=_text(claims, wire.T_OPERATOR),
        document=_text(claims, wire.T_DOC_NUMBER),
        location=_text(claims, wire.T_ISSUER_LOCATION),
        transaction_type=_text(claims, wire.T_TRANSACTION_TYPE))


def credential_id_str(raw: bytes) -> str:
    return str(uuid.UUID(bytes=raw))

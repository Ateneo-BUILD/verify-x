"""Offline verification: QR string -> verdict + claims.

This is the reference implementation of the open path. The Swift verifier
mirrors it step for step, and both are pinned against ``vectors/vectors.json``.

The verdict vocabulary is the load-bearing part. Three failure modes look
similar in code and mean completely different things to the person holding the
document, so they are kept strictly distinct:

* ``EXPIRED``      -- the credential's own ``expiresAt`` has passed. A real
                      finding about the document.
* ``DEVICE_STALE`` -- this device has no key for the credential's epoch. It says
                      nothing whatsoever about the document; the *device* needs
                      to sync. Rendering this as "expired" or "invalid" would be
                      a lie, and is the single most likely way for this design to
                      mislead someone in the field.
* ``FORGED``       -- the signature does not verify. The document is fake.

Order of operations is forced by sign-then-encrypt: decrypt first, then verify
the signature, and only then trust any claim. The AEAD proves the payload came
from someone holding an epoch key -- which is every verifier device -- so it is
*not* evidence of authenticity. Only the signature is.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import attachments, issuer, kdf, keystore, wire


class Verdict(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    FORGED = "forged"
    TAMPERED = "tampered"
    DEVICE_STALE = "device_stale"
    MALFORMED = "malformed"

    @property
    def is_document_fault(self) -> bool:
        """True when the verdict is a finding about the document itself.

        ``DEVICE_STALE`` is deliberately excluded -- it is a fault of this
        device, and the UI must say so rather than blaming the document.
        """
        return self in (Verdict.EXPIRED, Verdict.NOT_YET_VALID,
                        Verdict.FORGED, Verdict.TAMPERED)


@dataclass
class Result:
    verdict: Verdict
    detail: str = ""
    public_claims: dict = field(default_factory=dict)
    restricted_claims: dict = None
    epoch: int = None
    key_id: int = None
    needs_online_check: bool = False
    #: The organization named by the signing key's certificate, when it has
    #: one: the issuer a verifier may show as certified. None means the issuer
    #: claim is only as stated by the server.
    certified_issuer: str = None
    #: The attachment entries this device can read: the public list, then
    #: the restricted one where that section opened. Content split across
    #: part symbols is opened by ``attachments.Collector``.
    attachments: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.VALID


@dataclass
class TrustList:
    """Issuer public keys, by key id. Refreshed with each key bundle.

    ``windows`` maps a key id to the (not_before, not_after) its bundle entry
    gave it: the only span a credential it signed may claim to be issued in.
    ``certified`` maps a key id to the organization its certificate names, for
    keys that belong to one organization.

    Both are required, and every key needs a window: a list that judges a
    credential applies every check a phone does, so a server opens nothing
    a phone would refuse. ``bare`` is the one way round it, for a list that
    only checks a bundle's signature, and for tests.
    """
    keys: dict
    windows: dict
    certified: dict
    #: Set by ``bare`` only: no window and no certified issuer is checked.
    unchecked: bool = False

    def __post_init__(self):
        if self.unchecked:
            return
        if not isinstance(self.windows, dict) or not isinstance(self.certified, dict):
            raise TypeError("a trust list needs windows and certified issuers; "
                            "TrustList.bare is for signature checks only")
        missing = sorted(set(self.keys) - set(self.windows))
        if missing:
            raise ValueError("keys %s have no window" % missing)

    @classmethod
    def bare(cls, keys: dict) -> "TrustList":
        """Keys alone: no window and no certified issuer.

        What checks a bundle's or a statement's signature, and what old
        tests verify credentials against. It judges a credential by its
        signature and expiry only, skipping the key-window and issuer
        checks, so no server's verdict may rest on one.
        """
        return cls(keys, {}, {}, unchecked=True)

    def get(self, key_id: int):
        return self.keys.get(key_id)

    def window(self, key_id: int):
        return self.windows.get(key_id)

    def certified_issuer(self, key_id: int):
        return self.certified.get(key_id)


@dataclass
class EpochPrivateKeys:
    """What one device holds for one epoch.

    ``restricted_tier`` is None on a public-tier device -- it simply never
    receives that key, so it cannot open the restricted section at all.
    """
    epoch: int
    public_tier: object
    restricted_tier: object = None


# Tolerance for honest clock drift between the issuing host and the phone.
DEFAULT_SKEW_SECONDS = 300


def verify(qr_text, *, epoch_keys, trust_list, now,
           revocation=None, skew_seconds=DEFAULT_SKEW_SECONDS) -> Result:
    """Verify a scanned QR string entirely offline.

    ``epoch_keys`` maps epoch number -> EpochPrivateKeys.
    ``now`` is a unix timestamp, supplied by the caller so that clock policy
    (see TrustedClock on the device) stays outside the crypto.
    """
    try:
        raw = issuer.from_qr_string(qr_text)
        payload = wire.Payload.unpack(raw)
    except (wire.WireError, ValueError) as exc:
        return Result(Verdict.MALFORMED, str(exc))

    header = payload.header
    keys = epoch_keys.get(header.epoch)
    if keys is None:
        return Result(
            Verdict.DEVICE_STALE,
            "no key for epoch %d -- this device needs to sync" % header.epoch,
            epoch=header.epoch)

    header_bytes = header.pack()

    # 1. Open the public section.
    try:
        key, nonce = kdf.recipient_derive(keys.public_tier, header.eph_pub,
                                          header_bytes, kdf.TIER_PUBLIC)
        plain = AESGCM(key).decrypt(
            nonce, payload.public_ct + payload.public_tag,
            header_bytes + wire.AAD_PUBLIC)
    except (InvalidTag, ValueError):
        return Result(Verdict.TAMPERED, "public section failed authentication",
                      epoch=header.epoch)

    try:
        section = wire.PublicSection.unpack(plain)
    except wire.WireError as exc:
        return Result(Verdict.MALFORMED, str(exc), epoch=header.epoch)
    # No restricted section, no hash of one: 32 zero bytes, so one credential
    # is not signed under two.
    if not header.has_restricted and section.res_hash != issuer.ZERO_HASH:
        return Result(Verdict.MALFORMED,
                      "a restricted-section hash with no restricted section",
                      epoch=header.epoch)

    # 2. Verify the signature before trusting any claim.
    if section.sig_alg not in (wire.SIG_ECDSA_P256_SHA256, wire.SIG_ED25519):
        return Result(Verdict.FORGED,
                      "unsupported signature algorithm %d" % section.sig_alg,
                      epoch=header.epoch, key_id=section.key_id)

    issuer_key = trust_list.get(section.key_id)
    if issuer_key is None:
        return Result(Verdict.FORGED,
                      "unknown issuer key %d" % section.key_id,
                      epoch=header.epoch, key_id=section.key_id)

    signed = wire.signed_bytes(
        header.version, header.suite, header.flags, header.epoch,
        section.claims, section.res_hash, section.sig_alg, section.key_id)
    # The declared algorithm is passed in, so a credential claiming one
    # algorithm against a key of another type is rejected rather than quietly
    # verified -- the shape of an algorithm-confusion attack.
    if not keystore.verify(issuer_key, signed, section.sig, section.sig_alg):
        return Result(Verdict.FORGED, "signature does not verify",
                      epoch=header.epoch, key_id=section.key_id)

    try:
        claims_bytes = (wire.inflate(section.claims)
                        if header.flags & wire.FLAG_PUBLIC_DEFLATED
                        else section.claims)
        public_claims = wire.decode_claims(claims_bytes)
        _check_public_claims(public_claims)
        entries = attachments.entries_of(public_claims)
    except wire.WireError as exc:
        return Result(Verdict.MALFORMED, str(exc), epoch=header.epoch)

    # An organization's key vouches for that organization only. A credential
    # naming any other issuer was signed for a lie, whatever its signature.
    certified = trust_list.certified_issuer(section.key_id)
    if certified is not None:
        stated = public_claims.get(wire.T_ISSUER_ID)
        # Bytes, not text: the app compares the UTF-8 it was sent, and two
        # spellings that Unicode calls equal are still two names.
        if stated is None or stated != certified.encode("utf-8"):
            return Result(Verdict.FORGED,
                          "issuer does not match key %d's certificate"
                          % section.key_id,
                          epoch=header.epoch, key_id=section.key_id)

    result = Result(Verdict.VALID, public_claims=public_claims,
                    epoch=header.epoch, key_id=section.key_id,
                    certified_issuer=certified, attachments=entries)

    # 3. Open the restricted section if this device is entitled to it.
    #    A public-tier device stops here with a fully verified credential --
    #    that is what res_hash buys.
    if header.has_restricted and keys.restricted_tier is not None:
        try:
            key, nonce = kdf.recipient_derive(
                keys.restricted_tier, header.eph_pub, header_bytes,
                kdf.TIER_RESTRICTED)
            res_plain = AESGCM(key).decrypt(
                nonce, payload.restricted_ct + payload.restricted_tag,
                header_bytes + wire.AAD_RESTRICTED)
        except (InvalidTag, ValueError):
            return Result(Verdict.TAMPERED,
                          "restricted section failed authentication",
                          epoch=header.epoch, key_id=section.key_id)

        # Binds the restricted section to the signature. Without this check a
        # restricted section could be lifted from one credential onto another.
        if hashlib.sha256(res_plain).digest() != section.res_hash:
            return Result(Verdict.TAMPERED,
                          "restricted section does not match the signed hash",
                          epoch=header.epoch, key_id=section.key_id)

        try:
            res_bytes = (wire.inflate(res_plain)
                         if header.flags & wire.FLAG_RESTRICTED_DEFLATED
                         else res_plain)
            result.restricted_claims = wire.decode_claims(res_bytes)
            _check_tier(result.restricted_claims, restricted=True)
            # Both lists now, so an id in both is caught.
            result.attachments = attachments.entries_of(
                public_claims, result.restricted_claims)
        except wire.WireError as exc:
            return Result(Verdict.MALFORMED, str(exc), epoch=header.epoch)

    # 4. Validity window. This -- and only this -- is the document's own expiry.
    #    Both lengths were checked with the claims, so neither read can fail.
    expires = public_claims.get(wire.T_EXPIRES_AT)
    if expires is not None and wire.read_u32(expires) < now - skew_seconds:
        result.verdict = Verdict.EXPIRED
        result.detail = "credential expired at %d" % wire.read_u32(expires)
        return result

    issued = public_claims.get(wire.T_ISSUED_AT)
    if issued is not None and wire.read_u32(issued) > now + skew_seconds:
        result.verdict = Verdict.NOT_YET_VALID
        result.detail = "credential not valid until %d" % wire.read_u32(issued)
        return result

    # The signing key's window, after expiry on purpose: an old credential
    # reads expired, not forged. A key that signs outside its window, or a
    # credential that does not say when it was issued, is a forgery -- a key
    # stolen after its window closed can only backdate into it.
    window = trust_list.window(section.key_id)
    if window is not None:
        not_before, not_after = window
        if (issued is None
                or not (not_before - skew_seconds
                        <= wire.read_u32(issued)
                        <= not_after + skew_seconds)):
            result.verdict = Verdict.FORGED
            result.detail = ("credential issued outside key %d's window"
                             % section.key_id)
            return result

    # 5. Revocation is advisory only. The filter is probabilistic, so a hit
    #    raises "check online", never "invalid".
    cred_id = public_claims.get(wire.T_CREDENTIAL_ID)
    if revocation is not None and cred_id is not None and cred_id in revocation:
        result.needs_online_check = True
        result.detail = "possibly revoked -- confirm online before accepting"

    return result


def _check_tier(claims: dict, *, restricted: bool) -> None:
    """Each section holds its own tier's tags only: a restricted tag in the
    public section would be read by every phone, whoever signed it."""
    for tag in claims:
        if tag == 0 or (tag >= 0x40) != restricted:
            raise wire.WireError(
                "claim 0x%02x does not belong in the %s section"
                % (tag, "restricted" if restricted else "public"))


def _check_public_claims(claims: dict) -> None:
    """What every credential's public section must say, in the form it
    must say it.

    A credential id, because without one nothing can revoke it; and the
    times as 4 bytes each, so a signed credential with a timestamp of
    another length is malformed on both platforms, not an exception here and
    an unchecked expiry on the phone.
    """
    _check_tier(claims, restricted=False)
    credential_id = claims.get(wire.T_CREDENTIAL_ID)
    if credential_id is None or len(credential_id) != 16:
        raise wire.WireError("credential id missing or not 16 bytes")
    for tag in (wire.T_ISSUED_AT, wire.T_EXPIRES_AT):
        if tag in claims and len(claims[tag]) != 4:
            raise wire.WireError("%s is not 4 bytes" % wire.TAG_NAMES[tag])

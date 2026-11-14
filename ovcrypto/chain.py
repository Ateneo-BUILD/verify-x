"""Certificate checks for issuer keys certified by the deployment's issuing CA.

The phone pins the issuing CA, not a key, so any key that CA certifies can be
published without an app update. That makes what a certificate must say part
of the trust rule, and this is its reference: the signer checks a
certificate with it before installing one, the tests pin it, and
``Crypto/IssuerChain.swift`` must agree case for case
(``vectors/chains.json``).

A chain is the leaf, and for an organization key at most one CA between it
and the pinned one: the deployment's Organization CA, which the signer holds
so that verify can issue organization certificates itself. The pinned CA is
never sent.

What a leaf must be:

* signed directly by a pinned CA, or by an Organization CA that a pinned CA
  signed directly; every certificate valid at the time checked;
* ECDSA with SHA-256 or SHA-384, and nothing else;
* a P-256 key;
* key usage present, critical, ``digitalSignature``, not ``keyCertSign``;
* not a CA;
* one or both of the two EKUs below, and no other critical extension;
* for an organization key (the credential EKU only), exactly one O and one
  ``organizationIdentifier``; a deployment key (the infrastructure EKU) names
  no organization, and is never certified through an Organization CA.

What an Organization CA must be: under a pinned CA whose path length allows
one CA below it; ECDSA with SHA-256 or SHA-384; basicConstraints critical,
``cA`` true, path length 0; key usage with ``keyCertSign``; a P-256 key; the
credential EKU and not the infrastructure EKU, so whatever it certifies can
sign credentials and nothing else; no other critical extension; and a
subjectAltName listing, as a dNSName, the domain the phone paired with over
HTTPS (``domain``), and nothing but dNSNames. That last ties the CA to the
site whose own HTTPS certificate the phone checked, so a System CA made for
one deployment certifies nothing on a phone paired with another.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

#: Signs bundles, revocation feeds and log-key statements. The deployment key.
INFRASTRUCTURE_EKU = x509.ObjectIdentifier(
    "2.25.121329492992163728507773796270407157063")
#: Signs credentials. The deployment key and every organization key.
CREDENTIAL_EKU = x509.ObjectIdentifier(
    "2.25.257295685451493198219629212801851907755")

INFRASTRUCTURE = "infrastructure"
CREDENTIAL = "credential"

ALLOWED_SIGNATURES = (SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                      SignatureAlgorithmOID.ECDSA_WITH_SHA384)

_UNDERSTOOD_CRITICAL = {ExtensionOID.KEY_USAGE, ExtensionOID.BASIC_CONSTRAINTS,
                        ExtensionOID.EXTENDED_KEY_USAGE}

#: What cryptography raises reading a certificate it parsed but cannot use: a
#: curve or key type it does not know, among others. A reason here, never an
#: escape.
_UNREADABLE = (UnsupportedAlgorithm, ValueError, TypeError)


class ChainError(ValueError):
    """A certificate that does not vouch for its key. ``reason`` is stable."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s%s" % (reason, ": " + detail if detail else ""))
        self.reason = reason


@dataclass(frozen=True)
class CertifiedKey:
    spki: bytes                 # DER SubjectPublicKeyInfo of the leaf
    classes: frozenset          # INFRASTRUCTURE and/or CREDENTIAL
    organization: str = None    # the certificate's O, for an organization key
    organization_id: str = None  # its organizationIdentifier
    #: The latest notBefore of the certificates sent: the leaf and its
    #: Organization CA. Not the pinned CA's, which is checked at the time
    #: instead: a renewal issued after a key was certified would otherwise
    #: take that key's earlier credentials with it.
    not_before: int = 0
    not_after: int = 0          # earliest notAfter along the chain
    ca_name: str = ""           # what the phone says certified it
    intermediate_spki: bytes = None  # the Organization CA's key, if any

    @property
    def is_organization_key(self) -> bool:
        return self.organization_id is not None


@dataclass(frozen=True)
class CertifiedCA:
    """An Organization CA certificate the signer may install."""
    spki: bytes
    name: str                   # its CN: what phones say certified its keys
    not_before: int             # its own (not its pinned CA's, as for a key)
    not_after: int
    domains: tuple = ()         # its dNSNames that can match (``ca_domains``)


def _ts(dt) -> int:
    return int(dt.timestamp())


#: What the phone says when a CA's name cannot be read as the app reads it.
PINNED_CA_FALLBACK = "the pinned issuing CA"
ORGANIZATION_CA_FALLBACK = "the Organization CA"


def _ca_name(ca: x509.Certificate, fallback: str) -> str:
    """The CA's first CN, read as the app reads names (UTF8String or
    PrintableString only), or ``fallback``."""
    _, _, attributes = _names(ca.tbs_certificate_bytes)
    names = _strings(attributes, OID_COMMON_NAME)
    return names[0] if names else fallback


#: A dNSName that can match: letters, digits, dots and hyphens. Anything else
#: (a wildcard, a space, a byte past ASCII) matches nothing, and is no fault.
_DOMAIN = re.compile(r"[A-Za-z0-9.-]{1,253}")


def ca_domains(cert: x509.Certificate) -> tuple:
    """The certificate's dNSNames that can match a domain, in lowercase.

    Compared whole and case-insensitively: no wildcards, and a trailing dot
    is part of the name. The app reads the same (``IssuerChain.dnsNames``).
    """
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return ()
    return tuple(name.lower() for name in san.get_values_for_type(x509.DNSName)
                 if _DOMAIN.fullmatch(name))


def _only_domain_names(cert: x509.Certificate) -> bool:
    """Whether every name in the subjectAltName, if any, is a dNSName. A
    System CA lists the sites it is for and nothing else, which also keeps
    the app's reader from having to judge every other kind of name exactly
    as cryptography does."""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return True
    return all(isinstance(name, x509.DNSName) for name in san)


def _for_domain(mid: x509.Certificate, domain) -> bool:
    """Whether the Organization CA lists ``domain``, and only domain names.
    None, a phone that checked no site's HTTPS certificate, matches
    nothing."""
    return (isinstance(domain, str) and _DOMAIN.fullmatch(domain) is not None
            and _only_domain_names(mid) and domain.lower() in ca_domains(mid))


def _check_validity(cert: x509.Certificate, at: int, what: str) -> None:
    if not (_ts(cert.not_valid_before_utc) <= at <= _ts(cert.not_valid_after_utc)):
        raise ChainError("%s_not_valid_now" % what)


def _check_ca(ca: x509.Certificate, at: int) -> None:
    try:
        bc = ca.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        raise ChainError("ca_not_a_ca")
    if not bc.ca:
        raise ChainError("ca_not_a_ca")
    try:
        ku = ca.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not ku.key_cert_sign:
            raise ChainError("ca_not_a_ca")
    except x509.ExtensionNotFound:
        pass
    _check_validity(ca, at, "ca")


def load(der: bytes) -> x509.Certificate:
    """A certificate whose extensions all parse, or ``unparseable``.

    cryptography reads extensions lazily and raises on a malformed or
    repeated one wherever it is first touched; reading them here makes that
    one answer, as the app's reader gives it when it parses. A version-1
    certificate has no extensions (RFC 5280, 4.1.2.9); cryptography reads one
    that carries them anyway, and neither side accepts one.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
        extensions = cert.extensions
        version = cert.version
    except Exception as exc:  # cryptography raises ValueError and friends
        raise ChainError("unparseable", str(exc))
    if version is x509.Version.v1 and len(extensions):
        raise ChainError("unparseable", "a version 1 certificate with extensions")
    return cert


# -- names, read from the DER as the app reads them -------------------------
#
# cryptography decodes a Name lazily, by its own rules, and raises ValueError
# on some malformed ones; the app compares the raw bytes and reads only
# UTF8String and PrintableString values. These keep the two in step
# (Crypto/DERReader.swift, ParsedCertificate).

OID_COMMON_NAME = bytes.fromhex("550403")
OID_ORGANIZATION = bytes.fromhex("55040a")
OID_ORGANIZATION_ID = bytes.fromhex("550461")
_STRING_TAGS = (0x0C, 0x13)          # UTF8String, PrintableString


def _tlv(buf: bytes, i: int, end: int):
    """(tag, content start, content end) of the DER element at ``i``."""
    if i + 2 > end:
        raise ValueError("truncated")
    tag, n = buf[i], buf[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 4 or j + k > end:
            raise ValueError("bad length")
        n = int.from_bytes(buf[j:j + k], "big")
        j += k
    if j + n > end:
        raise ValueError("truncated")
    return tag, j, j + n


def _children(buf: bytes, start: int, end: int):
    out, i = [], start
    while i < end:
        tag, s, e = _tlv(buf, i, end)
        out.append((tag, s, e, i))
        i = e
    return out


def _names(tbs: bytes):
    """(issuer DER, subject DER, [(oid, tag, value)] of the subject)."""
    tag, s, e = _tlv(tbs, 0, len(tbs))
    if tag != 0x30 or e != len(tbs):
        raise ValueError("tbs")
    fields = _children(tbs, s, e)
    if fields and fields[0][0] == 0xA0:
        fields = fields[1:]
    if len(fields) < 6 or fields[2][0] != 0x30 or fields[4][0] != 0x30:
        raise ValueError("names")
    issuer = tbs[fields[2][3]:fields[2][2]]
    _, ss, se, sraw = fields[4]
    attributes = []
    for rtag, rs, re_, _ in _children(tbs, ss, se):
        if rtag != 0x31:
            raise ValueError("rdn")
        for atag, a_s, a_e, _ in _children(tbs, rs, re_):
            pair = _children(tbs, a_s, a_e)
            if atag != 0x30 or len(pair) != 2 or pair[0][0] != 0x06:
                raise ValueError("attribute")
            attributes.append((tbs[pair[0][1]:pair[0][2]], pair[1][0],
                               tbs[pair[1][1]:pair[1][2]]))
    return issuer, tbs[sraw:se], attributes


def _strings(attributes, oid: bytes):
    """The values of ``oid`` that are UTF8String or PrintableString."""
    out = []
    for got, tag, value in attributes:
        if got == oid and tag in _STRING_TAGS:
            try:
                out.append(value.decode("utf-8"))
            except UnicodeDecodeError:
                pass
    return out


def _count(attributes, oid: bytes) -> int:
    return sum(1 for got, _tag, _value in attributes if got == oid)


#: The leaf and at most one Organization CA.
MAX_CHAIN = 2


def validate(leaf_der: bytes, anchors_der, at: int,
             intermediates=(), domain: str = None) -> CertifiedKey:
    """Check one leaf against the pinned issuing CAs at unix time ``at``.

    ``intermediates`` is empty, or the one Organization CA that certified the
    leaf, which must list ``domain``: the host of the site the phone paired
    with over HTTPS, or None if it checked none. Returns what it certifies,
    or raises ``ChainError`` with a stable reason. Never anything else:
    cryptography raises ValueError on some malformed certificates, and a
    caller that catches ``ChainError`` must not crash.
    """
    try:
        return _validate(leaf_der, anchors_der, at, tuple(intermediates),
                         domain)
    except ChainError:
        raise
    except _UNREADABLE as exc:
        raise ChainError("unparseable", str(exc))


def _signed_by_anchor(cert: x509.Certificate, issuer_name: bytes, anchors_der,
                      at: int, *, room: bool = False):
    """The pinned CA with ``cert``'s issuer name whose signature verifies,
    which is a CA valid at ``at`` and, when ``room`` (an Organization CA
    below it), whose path length allows one; or None if none signed it.

    Every candidate is tried: a build may pin a CA and its renewal under one
    name and key, and the expired one, listed first, must not refuse every
    chain the other still vouches for. Of those fit, the one that ends last;
    when some signed it and none is fit, the first one's fault is the
    reason. So the order they are pinned in decides nothing.
    """
    fault = best = None
    for der in anchors_der:
        candidate = load(der)
        try:
            _, ca_subject, _ = _names(candidate.tbs_certificate_bytes)
        except ValueError as exc:
            raise ChainError("unparseable", str(exc))
        if ca_subject != issuer_name:
            continue
        try:
            cert.verify_directly_issued_by(candidate)
        except (InvalidSignature, *_UNREADABLE):
            continue
        try:
            _check_ca(candidate, at)
            if room:
                path = candidate.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS).value.path_length
                if path is not None and path < 1:
                    raise ChainError("ca_path_length")
        except ChainError as exc:
            fault = fault or exc
            continue
        if best is None or candidate.not_valid_after_utc > best.not_valid_after_utc:
            best = candidate
    if best is None and fault is not None:
        raise fault
    return best


def _check_intermediate(ca: x509.Certificate, mid: x509.Certificate,
                        at: int, domain) -> None:
    """An Organization CA, under the pinned CA ``ca`` (already checked, its
    path length too), for ``domain``."""
    if mid.signature_algorithm_oid not in ALLOWED_SIGNATURES:
        raise ChainError("algorithm", mid.signature_algorithm_oid.dotted_string)
    try:
        bc = mid.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        ku = mid.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        raise ChainError("intermediate_not_a_ca")
    if not bc.critical or not bc.value.ca or not ku.key_cert_sign:
        raise ChainError("intermediate_not_a_ca")
    if bc.value.path_length != 0:
        raise ChainError("intermediate_path_length")
    _check_validity(mid, at, "intermediate")
    if not _is_p256(mid):
        raise ChainError("key_type")
    for ext in mid.extensions:
        if ext.critical and ext.oid not in _UNDERSTOOD_CRITICAL:
            raise ChainError("critical_extension", ext.oid.dotted_string)
    try:
        eku = mid.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        raise ChainError("intermediate_eku")
    if CREDENTIAL_EKU not in eku or INFRASTRUCTURE_EKU in eku:
        raise ChainError("intermediate_eku")
    if not _for_domain(mid, domain):
        raise ChainError("intermediate_domain",
                         "it lists %s%s, not %s" % (
                             ", ".join(ca_domains(mid)) or "no domain",
                             "" if _only_domain_names(mid)
                             else " and names other than domains",
                             domain or "a domain checked over HTTPS"))


def validate_organization_ca(ca_der: bytes, anchors_der, at: int, *,
                             domain: str) -> CertifiedCA:
    """An Organization CA certificate on its own, by the rules a phone applies
    to the middle of a chain, for the site at ``domain``. The signer runs it
    before installing one; the phone never needs it, since it only sees the
    CA beside a leaf."""
    try:
        mid = load(ca_der)
        try:
            issuer, _, _ = _names(mid.tbs_certificate_bytes)
        except ValueError as exc:
            raise ChainError("unparseable", str(exc))
        ca = _signed_by_anchor(mid, issuer, anchors_der, at, room=True)
        if ca is None:
            raise ChainError("unknown_ca")
        _check_intermediate(ca, mid, at, domain)
        if _ca_name(mid, "") == "":
            # Phones name it on every document it certifies.
            raise ChainError("intermediate_name", "no common name phones "
                             "can show (UTF8String or PrintableString)")
        return CertifiedCA(
            spki=mid.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo),
            name=_ca_name(mid, ""),
            not_before=_ts(mid.not_valid_before_utc),
            not_after=min(_ts(mid.not_valid_after_utc),
                          _ts(ca.not_valid_after_utc)),
            domains=ca_domains(mid))
    except ChainError:
        raise
    except _UNREADABLE as exc:
        raise ChainError("unparseable", str(exc))


def _is_p256(cert: x509.Certificate) -> bool:
    """Whether the certificate's key is P-256. A curve cryptography cannot
    read is not, rather than an exception."""
    try:
        key = cert.public_key()
    except _UNREADABLE:
        return False
    return (isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP256R1))


def _validate(leaf_der: bytes, anchors_der, at: int,
              intermediates: tuple, domain) -> CertifiedKey:
    if len(intermediates) > MAX_CHAIN - 1:
        raise ChainError("chain_length")
    leaf = load(leaf_der)
    try:
        leaf_issuer, _, leaf_attributes = _names(leaf.tbs_certificate_bytes)
    except ValueError as exc:
        raise ChainError("unparseable", str(exc))

    mid = None
    if intermediates:
        mid = load(intermediates[0])
        try:
            mid_issuer, mid_subject, _ = _names(mid.tbs_certificate_bytes)
        except ValueError as exc:
            raise ChainError("unparseable", str(exc))
        if mid_subject != leaf_issuer:
            raise ChainError("unknown_ca")
        try:
            leaf.verify_directly_issued_by(mid)
        except (InvalidSignature, *_UNREADABLE):
            # The app's reader too: a key it cannot load signed nothing.
            raise ChainError("unknown_ca")
        ca = _signed_by_anchor(mid, mid_issuer, anchors_der, at, room=True)
    else:
        ca = _signed_by_anchor(leaf, leaf_issuer, anchors_der, at)
    if ca is None:
        raise ChainError("unknown_ca")
    if mid is not None:
        _check_intermediate(ca, mid, at, domain)

    if leaf.signature_algorithm_oid not in ALLOWED_SIGNATURES:
        raise ChainError("algorithm", leaf.signature_algorithm_oid.dotted_string)
    _check_validity(leaf, at, "leaf")

    if not _is_p256(leaf):
        raise ChainError("key_type")
    key = leaf.public_key()

    exts = leaf.extensions
    for ext in exts:
        if ext.critical and ext.oid not in _UNDERSTOOD_CRITICAL:
            raise ChainError("critical_extension", ext.oid.dotted_string)

    try:
        ku_ext = exts.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    except x509.ExtensionNotFound:
        raise ChainError("key_usage")
    ku = ku_ext.value
    if not ku_ext.critical or not ku.digital_signature or ku.key_cert_sign:
        raise ChainError("key_usage")

    try:
        if exts.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca:
            raise ChainError("leaf_is_ca")
    except x509.ExtensionNotFound:
        pass

    try:
        eku = exts.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        raise ChainError("eku")
    classes = set()
    if INFRASTRUCTURE_EKU in eku:
        classes.add(INFRASTRUCTURE)
    if CREDENTIAL_EKU in eku:
        classes.add(CREDENTIAL)
    if not classes:
        raise ChainError("eku")
    if mid is not None and INFRASTRUCTURE in classes:
        raise ChainError("deployment_key_via_intermediate")

    organization = organization_id = None
    if INFRASTRUCTURE in classes:
        if _count(leaf_attributes, OID_ORGANIZATION_ID):
            raise ChainError("organization", "a deployment key names no organization")
    else:
        names = _strings(leaf_attributes, OID_ORGANIZATION)
        ids = _strings(leaf_attributes, OID_ORGANIZATION_ID)
        if (_count(leaf_attributes, OID_ORGANIZATION) != 1
                or _count(leaf_attributes, OID_ORGANIZATION_ID) != 1
                or len(names) != 1 or len(ids) != 1
                or not names[0] or not ids[0]):
            raise ChainError("organization",
                             "an organization key needs one O and one "
                             "organizationIdentifier, as UTF8String or "
                             "PrintableString")
        organization, organization_id = names[0], ids[0]

    sent = [leaf] if mid is None else [leaf, mid]
    path = sent + [ca]
    spki_der = (serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
    return CertifiedKey(
        spki=key.public_bytes(*spki_der),
        classes=frozenset(classes),
        organization=organization,
        organization_id=organization_id,
        not_before=max(_ts(c.not_valid_before_utc) for c in sent),
        not_after=min(_ts(c.not_valid_after_utc) for c in path),
        # Whoever signed the leaf: the Organization CA when there is one.
        ca_name=(_ca_name(mid, ORGANIZATION_CA_FALLBACK) if mid is not None
                 else _ca_name(ca, PINNED_CA_FALLBACK)),
        intermediate_spki=(mid.public_key().public_bytes(*spki_der)
                           if mid is not None else None),
    )


# --------------------------------------------------------------------------
# The envelope: {"<key_id>": ["<base64 DER leaf>", ...]} beside a bundle
# --------------------------------------------------------------------------

_CANONICAL_ID = re.compile(r"0|[1-9][0-9]{0,9}")


def encode_chains(chains: dict) -> dict:
    """``{key_id: certs}`` -> the JSON object ``/keys/`` returns.

    ``certs`` is the leaf's DER, or a sequence of DER, the leaf first and then
    its Organization CA.
    """
    out = {}
    for key_id, certs in sorted(chains.items()):
        if isinstance(certs, (bytes, bytearray)):
            certs = (certs,)
        out[str(key_id)] = [base64.b64encode(der).decode() for der in certs]
    return out


def decode_chains(obj) -> dict:
    """The JSON object back to ``{key_id: (leaf_der, *intermediates)}``.

    Anything malformed is dropped rather than raised: a chain is only ever a
    reason to trust a key more, so a missing one costs that key, nothing else.
    """
    out = {}
    if not isinstance(obj, dict):
        return out
    for key, value in obj.items():
        # Canonical decimal only, as the app reads it: " 16", "+16", "016"
        # and "1_6" would otherwise all name key 16.
        if not (isinstance(key, str) and _CANONICAL_ID.fullmatch(key)):
            continue
        key_id = int(key)
        if key_id > 0xFFFFFFFF:
            continue
        if (not isinstance(value, list) or not 1 <= len(value) <= MAX_CHAIN
                or not all(isinstance(v, str) for v in value)):
            continue
        try:
            out[key_id] = tuple(base64.b64decode(v, validate=True)
                                for v in value)
        except (ValueError, TypeError):
            continue
    return out


#: Domain separation for ``chains_digest``.
CHAINS_CONTEXT = b"OfflineVerifier/v1/chains\x00"


def chains_digest(chains: dict) -> bytes:
    """SHA-256 of ``{key_id: certs}`` in one canonical form, which the signer
    puts in the bundle it signs (``bundle.chains_entry``) and the phone
    checks against what arrived beside it.

    ``certs`` as ``decode_chains`` gives them, or the leaf's DER alone. Ids
    ascending; for each, ``u32 key_id | u8 count``, then ``u32 length | DER``
    per certificate, the leaf first.
    """
    out = bytearray(CHAINS_CONTEXT)
    for key_id in sorted(chains):
        certs = chains[key_id]
        if isinstance(certs, (bytes, bytearray)):
            certs = (certs,)
        out += struct.pack(">IB", key_id, len(certs))
        for der in certs:
            out += struct.pack(">I", len(der)) + bytes(der)
    return hashlib.sha256(bytes(out)).digest()

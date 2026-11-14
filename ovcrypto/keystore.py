"""Signing and key-wrapping backends. Self-hosted, no cloud dependency.

The issuer signing key is the one key in this system that must never be
distributed and never be recoverable from a compromised host. Everything here
exists to keep it that way on hardware you own.

**PKCS#11 is the primary backend** because one interface covers every option
worth considering, from free to serious:

    SoftHSM2          software token, no hardware      libsofthsm2.so
    TPM 2.0           already on most server boards    tpm2-pkcs11
    Nitrokey HSM 2    ~EUR 90, smartcard-class         opensc-pkcs11.so
    YubiHSM 2         ~USD 650, network-attachable     yubihsm_pkcs11.so

Even SoftHSM2 with no hardware is a real improvement over a PEM on disk: the key
lives in a separate process behind a PIN and is created `CKA_EXTRACTABLE=false`,
so application-level compromise yields signing *access* rather than the key
itself. Hardware makes that boundary physical. Pick by threat model and budget;
the code does not change.

**Secrets never come from environment variables in production.** The PKCS#11 PIN
and any file wrapping key are read from systemd's credential directory, so they
are decrypted by the TPM at unit start, exposed only to that unit, never in
`/proc/*/environ`, never in a process listing, and never in a shell history.
"""

from __future__ import annotations

import errno
import hashlib
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from .wire import SIG_ECDSA_P256_SHA256, SIG_ED25519

# Order of the P-256 base point.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_HALF_ORDER = P256_ORDER // 2

# DER SubjectPublicKeyInfo prefix for Ed25519. The whole SPKI is 44 bytes, so
# the raw key is simply the last 32.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SigningError(RuntimeError):
    pass


def is_production() -> bool:
    return os.environ.get("OV_ENV") == "production"


# --------------------------------------------------------------------------
# Secret loading
# --------------------------------------------------------------------------

def load_secret(name: str, env_fallback: str = "", allow_env: bool = None) -> bytes:
    """Read a secret from systemd's credential directory.

    ``LoadCredentialEncrypted=`` in the unit file decrypts it at start (TPM-bound
    if the host has a TPM) and places it in a tmpfs readable only by that unit.
    That is the self-hosted equivalent of a managed secret store, and it is why
    an environment-variable fallback is refused in production: env vars leak
    through ``/proc/<pid>/environ``, child processes, crash dumps and logs.

    ``allow_env`` lets the caller decide, because this module deliberately does
    not import Django and so cannot read ``settings.OV_ENV``. Leaving it None
    falls back to the ``OV_ENV`` environment variable, which is correct for a
    real deployment but invisible to ``override_settings`` in tests. The Django
    layer passes it explicitly so there is one authority, not two.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        path = os.path.join(creds_dir, name)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                return fh.read().strip()

    path = os.environ.get("OV_%s_FILE" % name.upper().replace("-", "_"), "")
    if path:
        _require_private_mode(path)
        with open(path, "rb") as fh:
            return fh.read().strip()

    if env_fallback:
        value = os.environ.get(env_fallback, "")
        if value:
            refuse_env = (not allow_env) if allow_env is not None else is_production()
            if refuse_env:
                raise SigningError(
                    "%s must not come from an environment variable in "
                    "production; use systemd LoadCredentialEncrypted= or "
                    "OV_%s_FILE" % (env_fallback, name.upper()))
            return value.encode()

    raise SigningError("secret %r not found" % name)


def _require_private_mode(path: str) -> None:
    """Refuse a secret file another account can read or change.

    On POSIX that is any group or other bit. On Windows, where those modes
    mean nothing, it is the file's access list: only this account, SYSTEM and
    Administrators (who can take any file, as root can) may hold more than the
    right to see its attributes, and one of them must own it, since an owner
    can always grant itself the rest. Close to the rule OpenSSH for Windows
    applies to a private key, which allows no right at all to anyone else but
    reads only plain allow entries; this refuses every kind of allow entry it
    cannot judge.
    """
    path = os.fspath(path)
    if os.name == "nt":
        _refuse_others(path, _windows_others(path), "file")
        return
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise SigningError(
            "%s is group/world accessible (mode %03o); chmod 600 it." % (path, mode))


def require_private_folder(path: str) -> None:
    """Refuse a folder for secrets that another account can read, add to or
    take, counting on Windows what it hands down to what is made in it: a
    key written into it would be open from its first byte, before anything
    could restrict it."""
    path = os.fspath(path)
    if os.name == "nt":
        _refuse_others(path, _windows_others(path, handed_down=True), "folder")
        return
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise SigningError(
            "%s is group/world accessible (mode %03o); chmod 700 it." % (path, mode))


def _refuse_others(path: str, others: list, what: str) -> None:
    if others:
        raise SigningError(
            "%s is open to %s, not only to this account. Restrict it: python "
            "-c \"from ovcrypto import keystore; keystore.restrict_to_owner("
            "r'%s')\" (a %s another account owns: make one of your own)."
            % (path, " and ".join(others), path, what))


def restrict_to_owner(path: str) -> None:
    """Make a secret file, or a folder for them, this account's alone.

    POSIX: mode 600 for a file, 700 for a folder. Windows: a protected access
    list, nothing inherited, granting full control to this account, SYSTEM
    and Administrators, which is what `_require_private_mode` accepts. What
    is made in such a folder inherits its list, so a key written there is
    private from its first byte.

    It replaces the list of whatever it is given, so give it only what was
    made for secrets: on a folder Windows passes the change down to
    everything in it.
    """
    path = os.fspath(path)
    folder = os.path.isdir(path)
    if os.name != "nt":
        os.chmod(path, 0o700 if folder else 0o600)
        return
    inherit = "OICI" if folder else ""
    _set_windows_dacl(path, "D:P" + "".join(
        "(A;%s;FA;;;%s)" % (inherit, sid)
        for sid in (_SYSTEM, _ADMINISTRATORS, _windows_user())))


# --------------------------------------------------------------------------
# Windows access lists. Loaded on first use, and only on Windows.
# --------------------------------------------------------------------------

_SYSTEM = "S-1-5-18"
_ADMINISTRATORS = "S-1-5-32-544"
_OWNER_RIGHTS = "S-1-3-4"
_CREATOR_OWNER = "S-1-3-0"
# SYNCHRONIZE, READ_CONTROL, FILE_READ_ATTRIBUTES, FILE_READ_EA: rights that
# show a file is there and what it is, never what is in it.
_HARMLESS = 0x00100000 | 0x00020000 | 0x80 | 0x8
_DENY_TYPES = {1, 6, 10, 12}
_ALLOW_TYPES = {0, 9}        # the two whose SID follows the mask
_INHERIT_ONLY = 0x08
_WIN = None


def _win():
    global _WIN
    if _WIN is None:
        import ctypes
        from ctypes import wintypes as w

        a = ctypes.WinDLL("advapi32", use_last_error=True)
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        p, pp = ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
        dword_p, bool_p = ctypes.POINTER(w.DWORD), ctypes.POINTER(w.BOOL)
        for name, args, result in (
                ("GetNamedSecurityInfoW",
                 [w.LPCWSTR, ctypes.c_int, w.DWORD, pp, pp, pp, pp, pp], w.DWORD),
                ("SetNamedSecurityInfoW",
                 [w.LPCWSTR, ctypes.c_int, w.DWORD, p, p, p, p], w.DWORD),
                ("GetAce", [p, w.DWORD, pp], w.BOOL),
                ("ConvertSidToStringSidW", [p, pp], w.BOOL),
                ("ConvertStringSecurityDescriptorToSecurityDescriptorW",
                 [w.LPCWSTR, w.DWORD, pp, p], w.BOOL),
                ("GetSecurityDescriptorDacl", [p, bool_p, pp, bool_p], w.BOOL),
                ("LookupAccountSidW",
                 [w.LPCWSTR, p, w.LPWSTR, dword_p, w.LPWSTR, dword_p,
                  ctypes.POINTER(ctypes.c_int)], w.BOOL),
                ("OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)],
                 w.BOOL),
                ("GetTokenInformation",
                 [w.HANDLE, ctypes.c_int, p, w.DWORD, dword_p], w.BOOL)):
            function = getattr(a, name)
            function.argtypes, function.restype = args, result
        k.GetCurrentProcess.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]
        k.LocalFree.argtypes, k.LocalFree.restype = [p], p
        _WIN = (ctypes, w, a, k)
    return _WIN


def _windows_failed(what: str):
    ctypes = _win()[0]
    return SigningError("cannot %s (Windows error %d)" % (what, ctypes.get_last_error()))


def _sid_string(psid) -> str:
    ctypes, _, a, k = _win()
    text = ctypes.c_void_p()
    if not a.ConvertSidToStringSidW(psid, ctypes.byref(text)):
        raise _windows_failed("read a SID")
    try:
        return ctypes.wstring_at(text.value)
    finally:
        k.LocalFree(text)


def _account_name(psid, sid: str) -> str:
    ctypes, w, a, _ = _win()
    name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
    name_size, domain_size, use = w.DWORD(256), w.DWORD(256), ctypes.c_int()
    if not a.LookupAccountSidW(None, psid, name, ctypes.byref(name_size), domain,
                               ctypes.byref(domain_size), ctypes.byref(use)):
        return sid
    return "%s\\%s" % (domain.value, name.value) if domain.value else name.value


def _windows_user() -> str:
    """This process's account, as a SID string."""
    ctypes, w, a, k = _win()
    token = w.HANDLE()
    if not a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise _windows_failed("open this process's token")
    try:
        size = w.DWORD()
        a.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
        buffer = ctypes.create_string_buffer(size.value)
        if not a.GetTokenInformation(token, 1, ctypes.addressof(buffer), size,
                                     ctypes.byref(size)):
            raise _windows_failed("read this process's account")
        # TOKEN_USER starts with the SID's address.
        return _sid_string(ctypes.c_void_p.from_buffer(buffer).value)
    finally:
        k.CloseHandle(token)


def _windows_others(path: str, handed_down: bool = False) -> list:
    """The accounts other than this one, SYSTEM and Administrators that can
    read, change or take `path`, by name; empty when there are none. With
    `handed_down`, a folder's, what it gives what is made in it counts too."""
    ctypes, _, a, k = _win()
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = a.GetNamedSecurityInfoW(
        path, 1, 0x1 | 0x4,  # a file; its owner and its access list
        ctypes.byref(owner), None, ctypes.byref(dacl), None,
        ctypes.byref(descriptor))
    if error in (2, 3):  # as os.stat says it on POSIX
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
    if error:
        raise SigningError("cannot read who may open %s (Windows error %d)"
                           % (path, error))
    try:
        trusted = {_SYSTEM, _ADMINISTRATORS, _windows_user()}
        if handed_down:
            trusted.add(_CREATOR_OWNER)   # whoever makes the file: this account
        others = []

        def add(psid, sid):
            name = _account_name(psid, sid)
            if name not in others:
                others.append(name)

        owner_sid = _sid_string(owner)
        if owner_sid not in trusted:
            add(owner, owner_sid)
        if not dacl.value:
            return others + ["everyone (it has no access list)"]
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        for index in range(count):
            ace = ctypes.c_void_p()
            if not a.GetAce(dacl, index, ctypes.byref(ace)):
                raise _windows_failed("read %s's access list" % path)
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            if kind in _DENY_TYPES or (flags & _INHERIT_ONLY and not handed_down):
                continue
            if kind not in _ALLOW_TYPES:
                others.append("an access entry of type %d" % kind)
                continue
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            sid = _sid_string(ace.value + 8)
            if (sid in trusted or not mask & ~_HARMLESS
                    or (sid == _OWNER_RIGHTS and owner_sid in trusted)):
                continue
            add(ace.value + 8, sid)
        return others
    finally:
        k.LocalFree(descriptor)


def _set_windows_dacl(path: str, sddl: str) -> None:
    ctypes, w, a, k = _win()
    descriptor = ctypes.c_void_p()
    if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None):
        raise _windows_failed("read the access list %r" % sddl)
    try:
        present, defaulted, dacl = w.BOOL(), w.BOOL(), ctypes.c_void_p()
        if not a.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                           ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise _windows_failed("read the access list %r" % sddl)
        if not present.value:
            # Set as it is, no list at all would let everyone in.
            raise SigningError("%r names no access list" % sddl)
        # Its access list, protected from what the folder above would add.
        error = a.SetNamedSecurityInfoW(path, 1, 0x4 | 0x80000000,
                                        None, None, dacl, None)
        if error:
            raise SigningError("cannot restrict %s (Windows error %d)" % (path, error))
    finally:
        k.LocalFree(descriptor)


# --------------------------------------------------------------------------
# Signature encoding
# --------------------------------------------------------------------------

def der_to_raw_p256(der: bytes) -> bytes:
    r, s = asym_utils.decode_dss_signature(der)
    return _normalise_low_s(r, s)


def _normalise_low_s(r: int, s: int) -> bytes:
    # ECDSA admits both s and n-s for the same message. Without normalising, the
    # same credential can be re-signed into a different byte string -- harmless
    # for authenticity, but it breaks any dedup or audit log keyed on the
    # signature.
    if s > P256_HALF_ORDER:
        s = P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_to_der_p256(raw: bytes) -> bytes:
    if len(raw) != 64:
        raise SigningError("raw ECDSA signature must be 64 bytes")
    return asym_utils.encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def verify(public_key_der: bytes, message: bytes, raw_sig: bytes,
           sig_alg: int = None) -> bool:
    """Verify a 64-byte signature. Returns False rather than raising.

    ``sig_alg`` is the algorithm the *message* declares. When given, the key must
    actually be of that type -- a mismatch is rejected rather than quietly
    verified under whatever the key happens to be, which is the shape of an
    algorithm-confusion attack. When omitted (key bundles, which carry no
    algorithm byte), the key's own type decides.
    """
    if len(raw_sig) != 64:
        return False
    try:
        key = serialization.load_der_public_key(public_key_der)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # A curve cryptography does not read verifies nothing, as on the
        # phone, and never escapes as another exception.
        return False

    if isinstance(key, ed25519.Ed25519PublicKey):
        if sig_alg not in (None, SIG_ED25519):
            return False
        return _verify_ed25519(public_key_der, message, raw_sig)
    if isinstance(key, ec.EllipticCurvePublicKey):
        if sig_alg not in (None, SIG_ECDSA_P256_SHA256):
            return False
        return verify_p256(public_key_der, message, raw_sig)
    return False


def is_issuer_key(public_key_der: bytes) -> bool:
    """Whether a SubjectPublicKeyInfo is a key a credential may name: P-256 or
    Ed25519. Anything else verifies nothing, here or on a phone, so a
    deployment that registered one would issue forgeries of its own."""
    try:
        key = serialization.load_der_public_key(public_key_der)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return False
    if isinstance(key, ed25519.Ed25519PublicKey):
        return True
    return (isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP256R1))


def verify_p256(public_key_der: bytes, message: bytes, raw_sig: bytes) -> bool:
    if len(raw_sig) != 64:
        return False
    s = int.from_bytes(raw_sig[32:], "big")
    # Reject high-s outright: signers here always emit low-s, so a high-s
    # signature is either malleated or from a foreign implementation.
    if not 0 < s <= P256_HALF_ORDER:
        return False
    if not 0 < int.from_bytes(raw_sig[:32], "big") < P256_ORDER:
        return False
    try:
        key = serialization.load_der_public_key(public_key_der)
        # P-256 and no other curve: the range checks above are P-256's, and
        # a secp256k1 key of the same size would verify about half the
        # signatures its holder made, where the app refuses them all.
        if not (isinstance(key, ec.EllipticCurvePublicKey)
                and isinstance(key.curve, ec.SECP256R1)):
            return False
        key.verify(raw_to_der_p256(raw_sig), message, ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
        return False


def _verify_ed25519(public_key_der: bytes, message: bytes, sig: bytes) -> bool:
    try:
        key = serialization.load_der_public_key(public_key_der)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            return False
        key.verify(sig, message)
        return True
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
        return False


# --------------------------------------------------------------------------
# Signing backends
# --------------------------------------------------------------------------

class SigningBackend:
    """Produces 64-byte signatures over a message."""

    key_id: int
    sig_alg: int = SIG_ECDSA_P256_SHA256

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError

    def public_key_der(self) -> bytes:
        raise NotImplementedError


@dataclass
class LocalSigningBackend(SigningBackend):
    """In-process key. Development, tests and vector generation only.

    Refuses to run when ``OV_ENV=production``: a private key that the web process
    can read is a private key an application-level compromise walks away with.
    """

    private_key: object
    key_id: int = 1
    sig_alg: int = SIG_ECDSA_P256_SHA256

    def __post_init__(self):
        if is_production():
            raise SigningError(
                "LocalSigningBackend must not be used in production; "
                "configure PKCS11SigningBackend")
        if isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            self.sig_alg = SIG_ED25519
        elif not (isinstance(self.private_key, ec.EllipticCurvePrivateKey)
                  and isinstance(self.private_key.curve, ec.SECP256R1)):
            # Whatever it signed would verify nowhere.
            raise SigningError("an issuer key is P-256 or Ed25519")

    @classmethod
    def generate(cls, key_id: int = 1,
                 sig_alg: int = SIG_ECDSA_P256_SHA256) -> "LocalSigningBackend":
        if sig_alg == SIG_ED25519:
            return cls(ed25519.Ed25519PrivateKey.generate(), key_id, SIG_ED25519)
        return cls(ec.generate_private_key(ec.SECP256R1()), key_id,
                   SIG_ECDSA_P256_SHA256)

    @classmethod
    def from_pem(cls, path: str, key_id: int = 1) -> "LocalSigningBackend":
        _require_private_mode(path)
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        return cls(key, key_id)

    def sign(self, message: bytes) -> bytes:
        if self.sig_alg == SIG_ED25519:
            return self.private_key.sign(message)
        return der_to_raw_p256(self.private_key.sign(message, ECDSA(hashes.SHA256())))

    def public_key_der(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)


@dataclass
class PKCS11SigningBackend(SigningBackend):
    """Signing on a PKCS#11 token. The private key never enters this process.

    Works unchanged against SoftHSM2, tpm2-pkcs11, Nitrokey HSM 2 and YubiHSM 2 --
    only ``module_path`` changes.

    Provision the key so it can never be exported, e.g. with SoftHSM2::

        softhsm2-util --init-token --slot 0 --label cl03-issuer \\
            --so-pin <so-pin> --pin <user-pin>
        pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \\
            --login --keypairgen --key-type EC:prime256v1 \\
            --label cl03-issuer-p256 --id 01 \\
            --usage-sign --private --sensitive

    ``--sensitive`` sets ``CKA_SENSITIVE`` and ``--private`` requires login;
    together they mean the private half cannot be read off the token even by a
    logged-in caller.
    """

    module_path: str
    token_label: str
    key_label: str
    key_id: int = 1
    sig_alg: int = SIG_ECDSA_P256_SHA256
    pin: bytes = field(default=b"", repr=False)
    _session: object = field(default=None, repr=False, compare=False)
    _public_der: bytes = field(default=None, repr=False, compare=False)

    def _open(self):
        if self._session is not None:
            return self._session
        try:
            import pkcs11
        except ImportError:
            raise SigningError(
                "python-pkcs11 is required for the PKCS#11 backend "
                "(pip install python-pkcs11)") from None

        pin = self.pin or load_secret("cl03-pkcs11-pin", "OV_PKCS11_PIN")
        lib = pkcs11.lib(self.module_path)
        token = lib.get_token(token_label=self.token_label)
        # Read-only: this process signs, it never provisions. Key creation is a
        # separate, deliberate, offline operation.
        self._session = token.open(user_pin=pin.decode() if isinstance(pin, bytes) else pin)
        return self._session

    def _key(self, object_class):
        import pkcs11
        session = self._open()
        try:
            return session.get_key(object_class=object_class, label=self.key_label)
        except pkcs11.exceptions.NoSuchKey:
            raise SigningError(
                "no %s labelled %r on token %r"
                % (object_class, self.key_label, self.token_label)) from None

    def sign(self, message: bytes) -> bytes:
        import pkcs11
        from pkcs11 import Mechanism

        key = self._key(pkcs11.ObjectClass.PRIVATE_KEY)
        if self.sig_alg == SIG_ED25519:
            # CKM_EDDSA already produces the 64-byte R||S form.
            return bytes(key.sign(message, mechanism=Mechanism.EDDSA))

        # CKM_ECDSA_SHA256 returns raw r||s concatenated, not DER, so there is
        # no DER unwrapping here -- only low-s normalisation.
        raw = bytes(key.sign(message, mechanism=Mechanism.ECDSA_SHA256))
        if len(raw) != 64:
            raise SigningError("expected a 64-byte ECDSA signature, got %d" % len(raw))
        return _normalise_low_s(int.from_bytes(raw[:32], "big"),
                                int.from_bytes(raw[32:], "big"))

    def public_key_der(self) -> bytes:
        if self._public_der is not None:
            return self._public_der

        import pkcs11
        from pkcs11 import Attribute
        from pkcs11.util.ec import encode_named_curve_parameters  # noqa: F401

        key = self._key(pkcs11.ObjectClass.PUBLIC_KEY)
        if self.sig_alg == SIG_ED25519:
            point = _der_octet_string_contents(bytes(key[Attribute.EC_POINT]))
            public = ed25519.Ed25519PublicKey.from_public_bytes(point)
        else:
            point = _der_octet_string_contents(bytes(key[Attribute.EC_POINT]))
            public = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), point)

        self._public_der = public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        return self._public_der


def _der_octet_string_contents(data: bytes) -> bytes:
    """Unwrap CKA_EC_POINT, which PKCS#11 stores as a DER OCTET STRING."""
    if not data or data[0] != 0x04:
        return data  # some tokens store the bare point
    if data[1] < 0x80:
        return data[2:2 + data[1]]
    length_bytes = data[1] & 0x7F
    length = int.from_bytes(data[2:2 + length_bytes], "big")
    return data[2 + length_bytes:2 + length_bytes + length]


# --------------------------------------------------------------------------
# Key wrapping for epoch private keys at rest
#
# Epoch private keys are the one secret that must be both protected at rest and
# exportable -- devices need them. So they cannot live on the token the way the
# signing key does; they are wrapped instead, and the wrapping key is what the
# token protects.
# --------------------------------------------------------------------------

WRAP_AAD = b"cl03-epoch-key"


class KeyWrapper:
    def wrap(self, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def unwrap(self, ciphertext: bytes) -> bytes:
        raise NotImplementedError


@dataclass
class FileKeyWrapper(KeyWrapper):
    """AES-256-GCM under a key held in systemd's credential directory.

    Weaker than the PKCS#11 wrapper -- the key is in process memory while the
    service runs -- but a genuine improvement over a secret in ``.env``: it is
    TPM-sealed at rest, visible only to this unit, and never in the environment.

    Use this when the token cannot do AES, and keep the *signing* key on the
    token regardless. Losing the epoch-wrapping key costs a re-sync of every
    device; losing the signing key costs every credential ever issued.
    """

    key: bytes = field(repr=False)

    def __post_init__(self):
        if len(self.key) != 32:
            raise SigningError("wrapping key must be 32 bytes")

    @classmethod
    def from_credential(cls, name: str = "cl03-epoch-wrap-key",
                        allow_env: bool = None) -> "FileKeyWrapper":
        raw = load_secret(name, "OV_EPOCH_WRAP_KEY", allow_env=allow_env)
        # Accept hex or raw; a 64-char hex file is easier to handle safely.
        if len(raw) == 64:
            try:
                raw = bytes.fromhex(raw.decode())
            except (ValueError, UnicodeDecodeError):
                pass
        return cls(raw)

    @classmethod
    def generate(cls) -> "FileKeyWrapper":
        if is_production():
            raise SigningError(
                "refusing to generate an ephemeral wrapping key in production; "
                "every stored epoch key would become unreadable on restart")
        return cls(os.urandom(32))

    def wrap(self, plaintext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        return nonce + AESGCM(self.key).encrypt(nonce, plaintext, WRAP_AAD)

    def unwrap(self, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(self.key).decrypt(ciphertext[:12], ciphertext[12:], WRAP_AAD)


@dataclass
class PKCS11KeyWrapper(KeyWrapper):
    """Envelope encryption with the unwrapping step on the token.

    Each epoch key gets a fresh AES-256 data key. The data key is wrapped with
    AES-KWP (``CKM_AES_KEY_WRAP_PAD``) by a non-extractable AES key on the token;
    the bulk encryption is AES-GCM in software. So the stored ciphertext can only
    be opened by a process that can talk to the token.

    AES-KWP rather than AES-GCM on the token because GCM's IV-handling in PKCS#11
    varies between implementations, while key wrap is deterministic and portable.

    Provision with::

        pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login \\
            --keygen --key-type AES:32 --label cl03-epoch-wrap \\
            --id 02 --usage-wrap --private --sensitive
    """

    module_path: str
    token_label: str
    key_label: str
    pin: bytes = field(default=b"", repr=False)
    _session: object = field(default=None, repr=False, compare=False)

    def _wrapping_key(self):
        try:
            import pkcs11
        except ImportError:
            raise SigningError(
                "python-pkcs11 is required for the PKCS#11 backend "
                "(pip install python-pkcs11)") from None

        if self._session is None:
            pin = self.pin or load_secret("cl03-pkcs11-pin", "OV_PKCS11_PIN")
            lib = pkcs11.lib(self.module_path)
            token = lib.get_token(token_label=self.token_label)
            self._session = token.open(
                user_pin=pin.decode() if isinstance(pin, bytes) else pin)
        try:
            return self._session.get_key(
                object_class=pkcs11.ObjectClass.SECRET_KEY, label=self.key_label)
        except pkcs11.exceptions.NoSuchKey:
            raise SigningError(
                "no secret key labelled %r on token %r"
                % (self.key_label, self.token_label)) from None

    def wrap(self, plaintext: bytes) -> bytes:
        import struct

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

        session = self._wrapping_key().session
        data_key = os.urandom(32)
        handle = session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: data_key,
            Attribute.TOKEN: False,
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        })
        wrapped = bytes(self._wrapping_key().wrap_key(
            handle, mechanism=Mechanism.AES_KEY_WRAP_PAD))
        handle.destroy()

        nonce = os.urandom(12)
        body = AESGCM(data_key).encrypt(nonce, plaintext, WRAP_AAD)
        return struct.pack(">H", len(wrapped)) + wrapped + nonce + body

    def unwrap(self, ciphertext: bytes) -> bytes:
        import struct

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

        length = struct.unpack_from(">H", ciphertext, 0)[0]
        wrapped = ciphertext[2:2 + length]
        rest = ciphertext[2 + length:]

        handle = self._wrapping_key().unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            mechanism=Mechanism.AES_KEY_WRAP_PAD,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False,
                      Attribute.TOKEN: False})
        data_key = bytes(handle[Attribute.VALUE])
        handle.destroy()

        return AESGCM(data_key).decrypt(rest[:12], rest[12:], WRAP_AAD)

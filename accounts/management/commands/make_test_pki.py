"""A test root and issuing CA, for a development site and testing only.

Production certificates come from the organisation's managed PKI. This stands
in for it on a development site: it makes a root and a dedicated issuing CA
(path length 1, so the signer's Organization CA may sit below it), and
certifies a signer's request with exactly the profile the real PKI must issue
(`ovcrypto.pki`): a deployment key, an organization key (`--org`), or the
Organization CA (`--org-ca`).

The Organization CA is the site's System CA, for the domain phones pair with
(`--domain`), as a real PKI must be told it apart from the request. Before
certifying, this checks that the request asks for exactly that domain and
that https://<domain>/ answers with a certificate valid for it
(`signer.sitecheck`); the CA is named "<domain> System CA".

The CA's private key is a credential-forging key for every development
build, so it is written OUTSIDE every repository -- never in this tree, a
worktree, or on a development server -- and readable by its owner only: mode
600, or on Windows an access list of this account, SYSTEM and
Administrators, which `--sign-csr` checks before it uses the key.

    python manage.py make_test_pki --init --out ../.cl03-test-pki
    python manage.py make_test_pki --print --out ../.cl03-test-pki
    python manage.py make_test_pki --sign-csr signer.csr --out ../.cl03-test-pki \\
        [--org <signing_id> | --org-ca --domain verify.example.ph] \\
        --cert-out signer.crt
"""

import base64
import hashlib
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ovcrypto import chain, keystore, pki

DAY = 86400
ROOT_DAYS = 15 * 365
CA_DAYS = 10 * 365
LEAF_DAYS = 730
ORG_CA_DAYS = 5 * 365

ROOT_KEY, ROOT_CERT = "root.key.pem", "root.crt.pem"
CA_KEY, CA_CERT, CA_DER = "ca.key.pem", "ca.crt.pem", "ca.der"


def _inside_a_repository(path: str) -> bool:
    """True for this project, or any folder under a git work tree."""
    path = os.path.abspath(path)
    base = os.path.abspath(str(settings.BASE_DIR))
    if os.path.normcase(path).startswith(os.path.normcase(base)):
        return True
    probe = path
    while True:
        if os.path.exists(os.path.join(probe, ".git")):
            return True
        parent = os.path.dirname(probe)
        if parent == probe:
            return False
        probe = parent


def _write_private(path: str, data: bytes):
    with open(path, "wb") as handle:
        handle.write(data)
    keystore.restrict_to_owner(path)


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


class Command(BaseCommand):
    help = "Make or use the development PKI: a test root and issuing CA."

    def add_arguments(self, parser):
        parser.add_argument("--out", required=True,
                            help="The folder holding the test PKI. Must be "
                                 "outside every repository.")
        action = parser.add_mutually_exclusive_group(required=True)
        action.add_argument("--init", action="store_true",
                            help="Create the root and issuing CA.")
        action.add_argument("--print", action="store_true", dest="show",
                            help="Print the issuing CA for the app and verify.")
        action.add_argument("--sign-csr", dest="csr",
                            help="Certify the key in this request.")
        parser.add_argument("--org", default="",
                            help="An organization's signing_id: certify an "
                                 "organization key for it.")
        parser.add_argument("--cert-out", default="",
                            help="Where to write the certificate (PEM).")
        parser.add_argument("--org-ca", action="store_true", dest="org_ca",
                            help="Certify the request as the Organization CA "
                                 "(from `cl03signer ca keygen`).")
        parser.add_argument("--domain", default="",
                            help="With --org-ca: the site phones pair with, "
                                 "which the System CA is for.")
        parser.add_argument("--days", type=int, default=None,
                            help="Lifetime in days (default 730 for a key, "
                                 "%d for the Organization CA)." % ORG_CA_DAYS)

    def handle(self, *args, **options):
        out = os.path.abspath(os.path.expanduser(options["out"]))
        if _inside_a_repository(out):
            raise CommandError(
                "%s is inside a repository. The test CA's key forges "
                "credentials for every dev build; keep it outside." % out)
        if options["init"]:
            self._init(out)
            self._show(out)
        elif options["show"]:
            self._show(out)
        else:
            self._sign(out, options)

    # -- the CAs ----------------------------------------------------------

    def _init(self, out: str):
        if os.path.exists(os.path.join(out, CA_KEY)):
            raise CommandError("%s already holds a test CA; not replacing it, "
                               "because every dev build pins it." % out)
        # A folder made here is private before anything is written in it,
        # and what is written inherits that, on Windows too. One that was
        # there must already be private, and is never restricted here: on
        # Windows that would rewrite the access of everything in it, and
        # --out names any folder.
        if not os.path.isdir(out):
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            os.mkdir(out, 0o700)
            keystore.restrict_to_owner(out)
        try:
            keystore.require_private_folder(out)
        except keystore.SigningError as exc:
            raise CommandError("Not writing a test CA there. %s" % exc) from None
        now = int(time.time())
        root_key = ec.generate_private_key(ec.SECP256R1())
        ca_key = ec.generate_private_key(ec.SECP256R1())
        root = pki.make_ca(root_key, "OfflineVerifier Test Root",
                           now - DAY, now + ROOT_DAYS * DAY,
                           serial=x509.random_serial_number(), path_length=2)
        # Path length 1: the signer's Organization CA, and nothing deeper.
        ca = pki.make_ca(ca_key, "OfflineVerifier Test Issuing CA",
                         now - DAY, now + CA_DAYS * DAY,
                         serial=x509.random_serial_number(),
                         issuer_key=root_key, issuer_cert=root, path_length=1)
        _write_private(os.path.join(out, ROOT_KEY), _pem_key(root_key))
        _write_private(os.path.join(out, CA_KEY), _pem_key(ca_key))
        with open(os.path.join(out, ROOT_CERT), "wb") as handle:
            handle.write(root.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(out, CA_CERT), "wb") as handle:
            handle.write(ca.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(out, CA_DER), "wb") as handle:
            handle.write(ca.public_bytes(serialization.Encoding.DER))
        self.stdout.write("test PKI -> %s" % out)

    def _load_ca(self, out: str):
        if os.path.exists(os.path.join(out, CA_KEY)):
            try:
                keystore._require_private_mode(os.path.join(out, CA_KEY))
            except keystore.SigningError as exc:
                raise CommandError(str(exc)) from None
        try:
            with open(os.path.join(out, CA_KEY), "rb") as handle:
                key = serialization.load_pem_private_key(handle.read(), None)
            with open(os.path.join(out, CA_CERT), "rb") as handle:
                cert = x509.load_pem_x509_certificate(handle.read())
        except OSError as exc:
            raise CommandError("No test CA in %s (%s). Run --init first."
                               % (out, exc))
        return key, cert

    def _show(self, out: str):
        _, ca = self._load_ca(out)
        der = ca.public_bytes(serialization.Encoding.DER)
        self.stdout.write("")
        self.stdout.write("CREDENTIAL_ISSUER_CA_FINGERPRINTS=%s" % fingerprint(der))
        self.stdout.write("")
        self.stdout.write("// %s, SHA-256 %s"
                          % (ca.subject.rfc4514_string(), fingerprint(der)))
        self.stdout.write("// Paste into IssuingCAs.swift, under #if !APP_STORE.")
        self.stdout.write('"%s"' % base64.b64encode(der).decode())

    # -- a signer's request ----------------------------------------------

    def _sign(self, out: str, options):
        from accounts.models import Organization

        ca_key, ca = self._load_ca(out)
        with open(options["csr"], "rb") as handle:
            data = handle.read()
        try:
            csr = (x509.load_pem_x509_csr(data) if data.lstrip().startswith(b"-----")
                   else x509.load_der_x509_csr(data))
        except ValueError as exc:
            raise CommandError("Not a certificate request: %s" % exc)

        profile, organization, organization_id = pki.DEPLOYMENT, None, None
        days = options["days"] or LEAF_DAYS
        if options["org"] and options["org_ca"]:
            raise CommandError("--org or --org-ca, not both.")
        domain = options["domain"]
        if domain and not options["org_ca"]:
            raise CommandError("--domain goes with --org-ca.")
        if options["org_ca"]:
            profile = pki.ORGANIZATION_CA
            days = options["days"] or ORG_CA_DAYS
            try:
                pki.check_site_domain(domain)
            except ValueError as exc:
                raise CommandError("--org-ca needs --domain, the site phones "
                                   "pair with: %s." % exc)
            asked = pki.request_domains(csr)
            if asked != [domain]:
                raise CommandError(
                    "The request is for %s, not %s. Check site_domain in the "
                    "signer's policy.toml." % (", ".join(asked) or "no domain",
                                               domain))
            from signer import sitecheck
            try:
                self.stdout.write(sitecheck.describe(sitecheck.check(domain)))
            except sitecheck.SiteCheckFailed as exc:
                raise CommandError("%s. Nothing was certified." % exc)
        elif options["org"]:
            org = Organization.objects.filter(signing_id=options["org"]).first()
            if org is None:
                raise CommandError("No organization has signing_id %s."
                                   % options["org"])
            if len(org.name) > 96:
                raise CommandError(
                    "%r is longer than the 96 characters a credential carries; "
                    "its certificate could never match." % org.name)
            profile = pki.ORGANIZATION
            organization, organization_id = org.name, str(org.signing_id)

        now = int(time.time())
        try:
            cert = pki.sign_csr(csr, ca_key, ca, profile, now - 300,
                                now + days * DAY,
                                serial=x509.random_serial_number(),
                                organization=organization,
                                organization_id=organization_id,
                                domain=domain or None)
            der = cert.public_bytes(serialization.Encoding.DER)
            anchors = [ca.public_bytes(serialization.Encoding.DER)]
            # The same check the signer and every phone will make. A
            # ChainError is a ValueError, so a certificate that fails it is
            # a refusal here too, never a traceback.
            if profile == pki.ORGANIZATION_CA:
                got = chain.validate_organization_ca(der, anchors, now,
                                                     domain=domain)
                classes = ("certifies organization keys as %s, for phones "
                           "paired with %s" % (got.name, domain))
            else:
                classes = ", ".join(sorted(
                    chain.validate(der, anchors, now).classes))
        except ValueError as exc:
            raise CommandError(str(exc))
        pem = cert.public_bytes(serialization.Encoding.PEM)
        if options["cert_out"]:
            with open(options["cert_out"], "wb") as handle:
                handle.write(pem)
            self.stdout.write("certificate -> %s" % options["cert_out"])
        else:
            self.stdout.write(pem.decode())
        self.stdout.write("%s, %s, valid to %s"
                          % (profile, classes,
                             cert.not_valid_after_utc.isoformat()))

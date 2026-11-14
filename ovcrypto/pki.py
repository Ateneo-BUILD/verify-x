"""Certificate builders: the development PKI, the fixtures, and the signer's
Organization CA.

In production the deployment key's certificate and the Organization CA's
own certificate come from the organisation's managed PKI, never from here;
the production uses are the signer's Organization CA certifying an
organization key it generated (``issue_leaf``, ``ORGANIZATION``), and the
rule for the site domain it is named after (``check_site_domain``). This module
also makes the test root and issuing CA that `make_test_pki` gives a dev site,
and the fixtures in ``vectors/chains.json``. All must produce exactly the
profiles ``chain.validate`` expects.

``leaf_builder`` and ``intermediate_builder`` take knobs so the fixtures can
make every wrong certificate the phone must refuse; ``issue_leaf`` and
``issue_organization_ca`` are the right ones.
"""

from __future__ import annotations

import datetime
import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .chain import CREDENTIAL_EKU, INFRASTRUCTURE_EKU

DEPLOYMENT = "deployment"
ORGANIZATION = "organization"
ORGANIZATION_CA = "organization-ca"

#: The Organization CA is the site's System CA, named after the domain phones
#: pair with, which its subjectAltName also lists.
SYSTEM_CA_SUFFIX = " System CA"
#: A common name holds 64 characters; the domain gets what the suffix leaves.
SITE_DOMAIN_MAX = 64 - len(SYSTEM_CA_SUFFIX)

_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def check_site_domain(domain) -> str:
    """``domain`` if a System CA can be for it, or ValueError saying why.

    A host name as a URL carries it: lowercase letters, digits and hyphens in
    two or more labels, with no wildcard, no trailing dot, no port, and not
    an IP address; at most ``SITE_DOMAIN_MAX`` characters.
    """
    if not isinstance(domain, str) or not domain:
        raise ValueError("a site domain is needed, such as verify.example.ph")
    if len(domain) > SITE_DOMAIN_MAX:
        raise ValueError("%r is longer than the %d characters a System CA's "
                         "name leaves for it" % (domain, SITE_DOMAIN_MAX))
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError("%r is not a host name in lowercase, such as "
                         "verify.example.ph" % domain)
    if labels[-1].isdigit():
        raise ValueError("%r is an address, not a domain" % domain)
    return domain


def system_ca_name(domain: str) -> str:
    """What phones say certified a key the site's System CA issued."""
    return check_site_domain(domain) + SYSTEM_CA_SUFFIX


def _dt(ts: int) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)


def _name(common_name: str, organization: str = None,
          organization_id: str = None) -> x509.Name:
    attrs = []
    if organization is not None:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organization_id is not None:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER,
                                        organization_id))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attrs)


def make_ca(key, common_name: str, not_before: int, not_after: int, *,
            serial: int, issuer_key=None, issuer_cert=None,
            path_length=0) -> x509.Certificate:
    """A root (no issuer given) or an issuing CA signed by ``issuer_cert``."""
    subject = _name(common_name)
    issuer_name = issuer_cert.subject if issuer_cert is not None else subject
    signing_key = issuer_key if issuer_key is not None else key
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer_name)
               .public_key(key.public_key())
               .serial_number(serial)
               .not_valid_before(_dt(not_before))
               .not_valid_after(_dt(not_after))
               .add_extension(x509.BasicConstraints(ca=True,
                                                    path_length=path_length),
                              critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=False, content_commitment=False,
                   key_encipherment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=True, crl_sign=True,
                   encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                   key.public_key()), critical=False))
    return builder.sign(signing_key, hashes.SHA256())


def leaf_builder(ca_key, ca_cert, public_key, not_before: int, not_after: int,
                 *, serial: int, common_name: str, organization: str = None,
                 organization_id: str = None, ekus=(CREDENTIAL_EKU,),
                 key_usage_critical=True, digital_signature=True,
                 key_cert_sign=False, is_ca=None, extra_critical=None,
                 hash_algorithm=None) -> x509.Certificate:
    """Any leaf, right or wrong. ``is_ca`` None leaves basicConstraints out."""
    builder = (x509.CertificateBuilder()
               .subject_name(_name(common_name, organization, organization_id))
               .issuer_name(ca_cert.subject)
               .public_key(public_key)
               .serial_number(serial)
               .not_valid_before(_dt(not_before))
               .not_valid_after(_dt(not_after))
               .add_extension(x509.KeyUsage(
                   digital_signature=digital_signature,
                   content_commitment=False, key_encipherment=False,
                   data_encipherment=False, key_agreement=False,
                   key_cert_sign=key_cert_sign, crl_sign=False,
                   encipher_only=False, decipher_only=False),
                   critical=key_usage_critical))
    if ekus:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(list(ekus)), critical=False)
    if is_ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None if not is_ca else 0),
            critical=True)
    if extra_critical is not None:
        builder = builder.add_extension(extra_critical, critical=True)
    return builder.sign(ca_key, hash_algorithm or hashes.SHA256())


def intermediate_builder(issuer_key, issuer_cert, public_key, not_before: int,
                         not_after: int, *, serial: int, common_name: str,
                         ekus=(CREDENTIAL_EKU,), path_length=0,
                         basic_constraints_critical=True, key_cert_sign=True,
                         extra_critical=None, hash_algorithm=None,
                         subject: x509.Name = None, dns_names=(),
                         subject_alt_name=None) -> x509.Certificate:
    """Any Organization CA certificate, right or wrong. ``subject`` replaces
    the one ``common_name`` would make; ``dns_names`` go in a subjectAltName,
    or ``subject_alt_name`` is one as given (an ``UnrecognizedExtension`` for
    a malformed one)."""
    builder = (x509.CertificateBuilder()
               .subject_name(subject or _name(common_name))
               .issuer_name(issuer_cert.subject)
               .public_key(public_key)
               .serial_number(serial)
               .not_valid_before(_dt(not_before))
               .not_valid_after(_dt(not_after))
               .add_extension(x509.BasicConstraints(ca=True,
                                                    path_length=path_length),
                              critical=basic_constraints_critical)
               .add_extension(x509.KeyUsage(
                   digital_signature=False, content_commitment=False,
                   key_encipherment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=key_cert_sign,
                   crl_sign=True, encipher_only=False, decipher_only=False),
                   critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                   public_key), critical=False))
    if ekus:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(list(ekus)), critical=False)
    if dns_names:
        subject_alt_name = x509.SubjectAlternativeName(
            [x509.DNSName(name) for name in dns_names])
    if subject_alt_name is not None:
        builder = builder.add_extension(subject_alt_name, critical=False)
    if extra_critical is not None:
        builder = builder.add_extension(extra_critical, critical=True)
    return builder.sign(issuer_key, hash_algorithm or hashes.SHA256())


def issue_organization_ca(issuer_key, issuer_cert, public_key, not_before: int,
                          not_after: int, *, serial: int, domain: str
                          ) -> x509.Certificate:
    """The Organization CA, as the managed PKI must issue it: a CA with path
    length 0 that can certify credential keys and nothing else, named
    "<domain> System CA" and listing ``domain``, the site phones pair with."""
    return intermediate_builder(issuer_key, issuer_cert, public_key,
                                not_before, not_after, serial=serial,
                                common_name=system_ca_name(domain),
                                dns_names=(domain,))


def request_domains(csr: x509.CertificateSigningRequest) -> list:
    """The dNSNames a certificate request asks for, as written."""
    try:
        san = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return san.get_values_for_type(x509.DNSName)


def issue_leaf(ca_key, ca_cert, public_key, profile: str, not_before: int,
               not_after: int, *, serial: int, organization: str = None,
               organization_id: str = None) -> x509.Certificate:
    """The right leaf for a profile, as the managed PKI must issue it."""
    if profile == DEPLOYMENT:
        return leaf_builder(ca_key, ca_cert, public_key, not_before, not_after,
                            serial=serial, common_name="Deployment signing key",
                            ekus=(INFRASTRUCTURE_EKU, CREDENTIAL_EKU),
                            is_ca=False)
    if profile == ORGANIZATION:
        if not organization or not organization_id:
            raise ValueError("an organization leaf needs a name and an id")
        return leaf_builder(ca_key, ca_cert, public_key, not_before, not_after,
                            serial=serial,
                            common_name="Credential signing key",
                            organization=organization,
                            organization_id=organization_id,
                            ekus=(CREDENTIAL_EKU,), is_ca=False)
    raise ValueError("unknown profile %r" % profile)


def sign_csr(csr: x509.CertificateSigningRequest, ca_key, ca_cert, profile: str,
             not_before: int, not_after: int, *, serial: int,
             organization: str = None,
             organization_id: str = None,
             domain: str = None) -> x509.Certificate:
    """Certify the key in a request, after checking the request's signature.

    The subject is set here from the profile, never taken from the request: a
    requester does not get to name the organization its key speaks for. An
    Organization CA is for ``domain``, which the PKI was told separately, and
    its request must ask for exactly that domain: a signer configured for
    another site is refused here, before anything is issued.

    The key must be P-256, as every phone requires: a certificate for any
    other key would certify something no chain check accepts.
    """
    try:
        key = csr.public_key()
        valid = csr.is_signature_valid
    except (UnsupportedAlgorithm, ValueError, TypeError):
        raise ValueError("the certificate request's key cannot be read") from None
    if not (isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP256R1)):
        raise ValueError("the certificate request's key is not P-256")
    if not valid:
        raise ValueError("the certificate request's signature does not verify")
    if profile == ORGANIZATION_CA:
        check_site_domain(domain)
        asked = request_domains(csr)
        if asked != [domain]:
            raise ValueError("the request is for %s, not %s"
                             % (", ".join(asked) or "no domain", domain))
        return issue_organization_ca(ca_key, ca_cert, csr.public_key(),
                                     not_before, not_after, serial=serial,
                                     domain=domain)
    return issue_leaf(ca_key, ca_cert, csr.public_key(), profile, not_before,
                      not_after, serial=serial, organization=organization,
                      organization_id=organization_id)


#: An EKU from outside this system, for fixtures that must be refused.
FOREIGN_EKU = ExtendedKeyUsageOID.CODE_SIGNING

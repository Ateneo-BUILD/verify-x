"""Does the site answer over HTTPS for its domain, as a phone checks it?

`cl03signer ca keygen` asks before it makes a System CA for `site_domain`, and
`make_test_pki --sign-csr --org-ca` before it certifies one, so neither names
a CA after a domain that does not serve the site with a valid certificate. The
system's trust store and host-name check decide, as iOS's do when a phone
pairs. A check by the people making the CA, not the trust rule: the phone
makes its own on every sync.
"""

from __future__ import annotations

import socket
import ssl


class SiteCheckFailed(Exception):
    pass


def _field(name, key):
    for rdn in name or ():
        for k, v in rdn:
            if k == key:
                return v
    return ""


def check(domain: str, *, timeout: float = 10.0, context=None,
          connect=socket.create_connection) -> dict:
    """What https://<domain>/ presented, or SiteCheckFailed saying why.

    Returns the certificate's issuer and last day, for the operator to read
    before going on.
    """
    ctx = context or ssl.create_default_context()
    try:
        with connect((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        raise SiteCheckFailed("https://%s/ has no certificate valid for %s: %s"
                              % (domain, domain, exc.verify_message or exc))
    except (OSError, ssl.SSLError) as exc:
        raise SiteCheckFailed("https://%s/ did not answer: %s" % (domain, exc))
    return {"domain": domain,
            "issuer": (_field(cert.get("issuer"), "commonName")
                       or _field(cert.get("issuer"), "organizationName")),
            "not_after": cert.get("notAfter", "")}


def describe(result: dict) -> str:
    return ("https://%s/ answers with a certificate for %s from %s, valid "
            "until %s." % (result["domain"], result["domain"],
                           result["issuer"] or "an unnamed CA",
                           result["not_after"]))

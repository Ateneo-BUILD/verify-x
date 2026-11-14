"""`cl03signer`: the operator's commands, over the admin socket.

The signer learns who is asking from the kernel (SO_PEERCRED), not from
anything typed here, so `by` in the ledger is the operator's own account.

    cl03signer status
    cl03signer keygen [--org <signing_id>]          # prints the request
    cl03signer install-cert <key_id> <cert.pem>
    cl03signer publish <key_id>                     # then a second operator:
    cl03signer confirm <confirmation>
    cl03signer activate <key_id>                    # retires the one it replaces
    cl03signer retire <key_id>                      # an active key needs a confirm
    cl03signer suspend|unsuspend <key_id>
    cl03signer withdraw <key_id>                    # needs a confirm
    cl03signer pause|resume <context|all>
    cl03signer legacy-end <key_id>                  # needs a confirm
    cl03signer revoked-remove <uuid>...             # needs a confirm
    cl03signer discard <key_id>                     # a key never published
    cl03signer ca keygen                            # prints the request
    cl03signer ca install <ca.pem> [--ca-id N]
    cl03signer ca withdraw <ca_id>                  # needs a confirm

Never retire a key before its successor is activated: `activate` retires it
through the switch gate, and a successor started after a retirement leaves
phones refusing it. The signer refuses `retire` of an active key while one
is published to take over; with none, it says what stops signing and waits
for a second operator.

`ca keygen` first checks that https://<site_domain>/ answers with a
certificate valid for that domain (`signer.sitecheck`): the System CA is
named after it, and phones trust it only for the site they paired with.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import uuid

from . import sitecheck
from .service import Refused
from .transport import call

DEFAULT_SOCKET = "/run/cl03-signer/admin.sock"


def _cert_der(path):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    with open(path, "rb") as handle:
        data = handle.read()
    cert = (x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data
            else x509.load_der_x509_certificate(data))
    return cert.public_bytes(serialization.Encoding.DER)


def main(argv=None):
    p = argparse.ArgumentParser(prog="cl03signer")
    p.add_argument("--socket", default=os.environ.get("OV_SIGNER_SOCKET",
                                                      DEFAULT_SOCKET))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("public")
    g = sub.add_parser("keygen")
    g.add_argument("--org", default=None)
    g = sub.add_parser("install-cert")
    g.add_argument("key_id", type=int)
    g.add_argument("cert")
    for name in ("publish", "activate", "retire", "suspend", "unsuspend",
                 "withdraw", "legacy-end", "discard"):
        sub.add_parser(name).add_argument("key_id", type=int)
    ca = sub.add_parser("ca").add_subparsers(dest="ca_cmd", required=True)
    ca.add_parser("keygen")
    g = ca.add_parser("install")
    g.add_argument("cert")
    g.add_argument("--ca-id", type=int, default=None)
    ca.add_parser("withdraw").add_argument("ca_id", type=int)
    sub.add_parser("confirm").add_argument("confirmation", type=int)
    for name in ("pause", "resume"):
        sub.add_parser(name).add_argument("context")
    sub.add_parser("revoked-remove").add_argument("ids", nargs="+")
    a = p.parse_args(argv)

    try:
        if a.cmd in ("status", "public"):
            result = call(a.socket, a.cmd)
        elif a.cmd == "keygen":
            result = call(a.socket, "keygen", organization=a.org)
            print(result.pop("csr"))
        elif a.cmd == "ca" and a.ca_cmd == "keygen":
            domain = call(a.socket, "public").get("site_domain")
            if domain:
                try:
                    print(sitecheck.describe(sitecheck.check(domain)),
                          file=sys.stderr)
                except sitecheck.SiteCheckFailed as exc:
                    print("refused: %s. The System CA is named after "
                          "site_domain; fix the site or policy.toml first."
                          % exc, file=sys.stderr)
                    return 1
            # Without one, the signer refuses and says so.
            result = call(a.socket, "ca_keygen")
            print(result.pop("csr"))
        elif a.cmd == "ca" and a.ca_cmd == "install":
            result = call(a.socket, "ca_install", ca_id=a.ca_id,
                          cert=base64.b64encode(_cert_der(a.cert)).decode())
        elif a.cmd == "ca":
            result = call(a.socket, "ca_withdraw", ca_id=a.ca_id)
        elif a.cmd == "install-cert":
            result = call(a.socket, "install_cert", key_id=a.key_id,
                          leaf=base64.b64encode(_cert_der(a.cert)).decode())
        elif a.cmd == "confirm":
            result = call(a.socket, "confirm", confirmation=a.confirmation)
        elif a.cmd in ("pause", "resume"):
            result = call(a.socket, a.cmd, context=a.context)
        elif a.cmd == "revoked-remove":
            result = call(a.socket, "revoked_remove",
                          ids=[base64.b64encode(uuid.UUID(i).bytes).decode()
                               for i in a.ids])
        else:
            result = call(a.socket, a.cmd.replace("-", "_"), key_id=a.key_id)
    except Refused as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())

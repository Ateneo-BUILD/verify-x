"""Build one demo `.pkpass`, to find out whether Wallet can carry the card.

    manage.py make_wallet_pass --out demo.pkpass \
        --cert ~/wallet/passcert.pem --key ~/wallet/passkey.pem \
        --wwdr ~/wallet/wwdr.pem --team ABCDE12345 \
        --pass-type pass.org.example.verify

The question this exists to answer is not "can we make a pass" -- that part
is mechanical. It is **whether a 963-character offline credential is legible
from a wallet screen**, which no render can settle: iOS draws the barcode and
gives no error-correction setting, so the density trade this project makes
everywhere else is not available. `--report` prints the sizing without
building anything, and needs no certificate.

By default the pass carries a synthetic payload of the right LENGTH and
charset rather than a real credential, because the density question is about
the module count and nothing else -- and a demo pass should not have somebody
in it. `--payload` takes a real one when the end-to-end test is the point.
"""

from __future__ import annotations

import os
import random
import string

from django.core.management.base import BaseCommand, CommandError

from accounts import sample_data, wallet_pass

#: The worst case the printed card is designed for: 121 modules, version 26.
#: A payload of this length is what the pass has to survive.
WORST_CASE_CHARS = 963


def synthetic_payload(length=WORST_CASE_CHARS, seed=7):
    """A credential-shaped string: a UUID, the tag, then base45 padding.

    Deterministic, so two people comparing a pass are comparing one pass.
    """
    rng = random.Random(seed)
    head = "AAEA5BF5-1D4C-4E3B-9C21-8B7F0A2D6E14:CL03:"
    alphabet = string.digits + string.ascii_uppercase + " $%*+-./:"
    return head + "".join(rng.choice(alphabet)
                          for _ in range(max(0, length - len(head))))


def _icon(size):
    """A plain mark, so the pass has the icon.png iOS requires."""
    import cv2
    import numpy as np

    img = np.zeros((size, size, 4), dtype=np.uint8)
    img[:, :, :3] = (155, 82, 0)          # BGR of #00529B
    img[:, :, 3] = 255
    ok, buf = cv2.imencode(".png", img)
    if not ok:
        raise CommandError("could not encode the icon")
    return buf.tobytes()


class Command(BaseCommand):
    help = "Build a demo Apple Wallet pass carrying the offline credential."

    def add_arguments(self, parser):
        parser.add_argument("--out", default="demo.pkpass")
        parser.add_argument("--cert", help="Pass Type ID certificate, PEM")
        parser.add_argument("--key", help="its private key, PEM")
        parser.add_argument("--wwdr", help="Apple WWDR G4 intermediate, PEM")
        parser.add_argument("--team", help="10-character Apple team id")
        parser.add_argument("--pass-type", help="pass.your.reverse.dns")
        parser.add_argument("--payload", help="a real credential, if testing "
                                              "end to end")
        parser.add_argument("--chars", type=int, default=WORST_CASE_CHARS,
                            help="length of the synthetic payload")
        # A pass signed by a personal team should not claim to come from an
        # agency. Name whoever is actually demonstrating it.
        parser.add_argument("--org", default="Verify (demo)",
                            help="what the pass says issued it")
        parser.add_argument("--report", action="store_true",
                            help="print the sizing and stop; needs no "
                                 "certificate")

    def handle(self, *args, **options):
        message = options["payload"] or synthetic_payload(options["chars"])

        self.stdout.write("barcode: " + wallet_pass.barcode_report(message))
        if options["report"]:
            return

        missing = [flag for flag in ("cert", "key", "wwdr", "team", "pass_type")
                   if not options.get(flag)]
        if missing:
            raise CommandError(
                "need --" + ", --".join(m.replace("_", "-") for m in missing)
                + " to sign. Run with --report to see the sizing without them.")

        read = lambda path: open(os.path.expanduser(path), "rb").read()

        values = sample_data.SAMPLE_VALUES
        pass_json = wallet_pass.build_pass_json(
            pass_type_id=options["pass_type"],
            team_id=options["team"],
            serial=message.split(":", 1)[0],
            organization_name=options["org"],
            description="National ID verification card",
            barcode_message=message,
            holder=values["full_name"],
            card_number=values["reference"],
            digital_id=values["code"],
            transaction_type="Civil registry document request",
            location="Window 3",
            verified_at="04/09/2026 10:42 AM",
            alt_text="")

        blob = wallet_pass.build(
            pass_json,
            {"icon.png": _icon(29), "icon@2x.png": _icon(58),
             "icon@3x.png": _icon(87), "logo.png": _icon(29)},
            certificate_pem=read(options["cert"]),
            private_key_pem=read(options["key"]),
            wwdr_pem=read(options["wwdr"]))

        with open(options["out"], "wb") as handle:
            handle.write(blob)
        self.stdout.write(self.style.SUCCESS(
            "wrote %s (%.1f KB)" % (options["out"], len(blob) / 1024.0)))
        self.stdout.write(
            "Mail it to yourself and open the attachment on the iPhone. "
            "The holder shown is the site's own sample record, not a real "
            "person.")

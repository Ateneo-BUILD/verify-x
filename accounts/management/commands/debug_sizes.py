"""What the captured responses do to the two symbols on the printed card.

Reads `DebugCapture` -- whole eVerify responses kept on a development instance
-- and reports, per capture, what the portrait symbol and the credential
symbol actually come out at. Sizes AND quality, because they trade against
each other: the portrait's bytes are bounded by the stamp at the 0.4 mm module
floor, and the only currency for buying room is face detail.

    python manage.py debug_sizes
    python manage.py debug_sizes --px 200 --px 160 --px 128
    python manage.py debug_sizes --stamp 48.8 --stamp 68.0

With no arguments it answers "is what we ship right for the faces we have
seen". With `--px` or `--stamp` it sweeps, which is what to run before moving
either constant.

**Only numbers come out of this.** The captures never leave the instance --
the same rule the original portrait compression study followed, and for the
same reason: these are real people's faces.
"""

from django.core.management.base import BaseCommand

from accounts import credentials, debug_store
from accounts.models import DebugCapture


class Command(BaseCommand):
    help = "Report portrait and credential symbol sizing over the debug store."

    def add_arguments(self, parser):
        parser.add_argument(
            "--px", type=int, action="append", default=None,
            help="Render resolution to try; repeatable. Defaults to what ships.")
        parser.add_argument(
            "--stamp", type=float, action="append", default=None,
            help="Portrait stamp width in mm to try; repeatable.")
        parser.add_argument(
            "--redact", action="store_true",
            help="Measure the Demo Mode render instead of the plain one.")

    def handle(self, *args, **options):
        # Successes only. A failed lookup is kept for what the upstream said,
        # not for what it would print -- it has no face and no fields, so it
        # would show up here as a row of misses and read as a broken capture.
        captures = list(DebugCapture.objects.filter(
            outcome=DebugCapture.OUTCOME_SUCCESS))
        faces = [c for c in captures if c.photo_data]
        self.stdout.write(
            "%d capture(s), %d with a face" % (len(captures), len(faces)))
        if not captures:
            self.stdout.write(
                "Nothing to measure. Run a verification on this instance "
                "with EVERIFY_DEBUG_CAPTURE set.")
            return

        pxs = options["px"] or [credentials.PORTRAIT_PX]
        stamps = options["stamp"] or [credentials.PORTRAIT_STAMP_MM]

        self.stdout.write("")
        self.stdout.write("PORTRAIT  (redact=%s)" % bool(options["redact"]))
        self.stdout.write(
            "  %-7s %-6s %-9s %-8s %-9s %-8s %s"
            % ("stamp", "px", "bytes", "version", "mm/module", "SSIM", "misses"))
        for stamp in stamps:
            for px in pxs:
                sizes, versions, ssims, misses = [], [], [], 0
                for capture in faces:
                    m = debug_store.measure_portrait(
                        capture.photo_data, px=px, stamp_mm=stamp,
                        redact=options["redact"])
                    if not m or not m["scannable"]:
                        misses += 1
                        continue
                    sizes.append(m["bytes"])
                    versions.append(m["version"])
                    if m["ssim"] is not None:
                        ssims.append(m["ssim"])
                if not sizes:
                    self.stdout.write("  %-7.1f %-6d nothing fits (%d face(s))"
                                      % (stamp, px, len(faces)))
                    continue
                self.stdout.write(
                    "  %-7.1f %-6d %-9s %-8s %-9.4f %-8s %d"
                    % (stamp, px,
                       "%d-%d" % (min(sizes), max(sizes)),
                       "v%d-v%d" % (min(versions), max(versions)),
                       stamp / (17 + 4 * max(versions)),
                       ("%.4f" % (sum(ssims) / len(ssims))) if ssims else "-",
                       misses))

        self.stdout.write("")
        self.stdout.write("CREDENTIAL  (stamp %.1f mm)" % credentials.STAMP_MM)
        rows = []
        for capture in captures:
            m = debug_store.measure_credential(
                capture.payload, organization=capture.organization)
            if m:
                rows.append(m)
        if not rows:
            self.stdout.write(
                "  not minted -- no issuer key on this instance, or no "
                "displayable fields in the captures.")
            return
        over = [r for r in rows if not r["scannable"]]
        self.stdout.write(
            "  %d measured   fields %d-%d   chars %d-%d   version v%d-v%d"
            % (len(rows),
               min(r["fields"] for r in rows), max(r["fields"] for r in rows),
               min(r["chars"] for r in rows), max(r["chars"] for r in rows),
               min(r["version"] for r in rows if r["version"]),
               max(r["version"] for r in rows if r["version"])))
        self.stdout.write(
            "  widest needs %.1f mm, printed at %.1f  --  %s"
            % (max(r["min_stamp_mm"] for r in rows if r["min_stamp_mm"]),
               credentials.STAMP_MM,
               "OK" if not over else "%d BELOW THE FLOOR" % len(over)))

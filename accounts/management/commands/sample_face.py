"""Write the drawn sample face out, or reprint what it costs to encode.

The face exists so a document can be looked at without a real person having
been verified to produce one, and so that the looking is not done against
`static/mock-face.png` -- a cartoon smiley, which has produced a wrong byte
figure in this repo more than once.

`--measure` prints the column in `accounts/sample_face.py`'s docstring. The
other column, the one from real captures, comes from `debug_sizes` on an
instance that has them, and that remains the measurement of record: this is a
stand-in, and its own docstring says where it is not one.
"""

from django.core.management.base import BaseCommand

from accounts import sample_face


class Command(BaseCommand):
    help = "Write or measure the synthetic sample face."

    def add_arguments(self, parser):
        parser.add_argument(
            "--out", default="",
            help="Write the face here as JPEG, to look at it.")
        parser.add_argument(
            "--measure", action="store_true",
            help="Print 200x200 grayscale WebP bytes by quality.")
        parser.add_argument(
            "--seed", type=int, default=7,
            help="Draw a different one. The shipped face is seed 7.")
        parser.add_argument(
            "--drawn", action="store_true",
            help="The drawn stand-in rather than the chosen portrait. "
                 "--measure always reports the drawn one.")

    def handle(self, *args, **options):
        seed = options["seed"]
        if options["out"]:
            blob = (sample_face.jpeg_bytes(seed)
                    if options["drawn"]
                    else sample_face.portrait_jpeg_bytes())
            with open(options["out"], "wb") as fh:
                fh.write(blob)
            self.stdout.write("wrote %s (%d bytes)"
                              % (options["out"], len(blob)))

        if options["measure"] or not options["out"]:
            import cv2

            img = sample_face.build(seed)
            grey = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            small = cv2.resize(grey, (200, 200),
                               interpolation=cv2.INTER_AREA)
            self.stdout.write("200x200 grayscale WebP, seed %d:" % seed)
            for quality in (10, 30, 50, 70, 90):
                encoded = cv2.imencode(
                    ".webp", small, [cv2.IMWRITE_WEBP_QUALITY, quality])[1]
                self.stdout.write("  q%-3d %5d bytes" % (quality,
                                                         len(encoded)))
            self.stdout.write(
                "  laplacian variance %.1f  (real captures: 335-463)"
                % cv2.Laplacian(small, cv2.CV_64F).var())
            self.stdout.write(
                "  real captures, same measure: q30 1140-1518, "
                "q50 1410-1968, q70 1724-2404, q90 3508-4884")

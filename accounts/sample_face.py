"""The sample person's face -- a chosen portrait, and a drawn stand-in.

`static/sample-id1.png` is what the sample document and the sample validation
page show: a photographic ID portrait of a woman who does not exist, so there
is no likeness to age out of a store and no consent to worry about. It
replaced the cel art of a cartoon character that `static/sample-face.png`
then held, which was the same in that respect and wrong in every other --
see below.

The drawn face below (`build()`) is the other thing in this module and it is
NOT what the sample shows. It exists for measuring, and the difference matters
because every byte figure in this repo about the printed card was measured off
a face:

`static/mock-face.png` is a cartoon smiley, and measuring on it produced a
wrong answer here more than once -- flat vector art compresses nothing like
skin. The real captures that corrected those numbers stay on the instance
that holds them. So `build()` draws a face that behaves like a photograph
where it matters: everything is composited through a **blurred alpha mask**,
because a hard vector edge is precisely what a face does not contain and
precisely what makes a drawing cheap to encode, and the rest is texture at
every scale -- skin unevenness, pores, hair strands, woven cloth, sensor grain.

200x200 grayscale WebP, which is what `credentials.render_portrait()`
produces, and bytes are the currency the portrait symbol is sized in:

    | quality | real faces | sample-id1 | drawn | sample-face | mock-face |
    | 30      | 1140-1518  | 1528       | 1094  | 2810        | 1188      |
    | 50      | 1410-1968  | 2050       | 1556  | 3480        | 1394      |
    | 70      | 1724-2404  | 2590       | 2026  | 4104        | 1584      |
    | 90      | 3508-4884  | 5016       | 4870  | 6772        | 2386      |

**The photograph is the only column that behaves like the left one.** It runs
a little over at every quality and its Laplacian variance is 632 against a
capture's 335-463, both for the same reason: it was generated at 1254 px and
has been through neither a webcam's optics nor its JPEG, while every capture
the band was measured from has. Simulating that stage was tried and is not
worth it -- downsampling collapses the sharpness long before it brings the
bytes down, because the excess is hair and background STRUCTURE rather than
fine detail. A few per cent over on an image that is actually a photograph is
not a number worth chasing.

**Read the two wrong columns as opposite failures.** The smiley is too CHEAP
at high quality, because flat fills collapse where skin does not. The chosen
portrait is too EXPENSIVE everywhere, because cel art is hard black outlines
and the encoder pays for every one of them at every quality. Neither is a
photograph, and a quality ladder run against either lands somewhere a real
face would not -- optimistically for one, pessimistically for the other.

**How expensive was visible in the symbol it got.** At the shipped 160 px the
cel art costs 908 bytes at quality 1, against a 701-byte budget, so nothing at
that resolution fitted and the sample document printed ONE symbol for as long
as that was the end of the story. `render_portrait_fitted()` walks the
resolution down and that picture lands at 136 px, where a real capture would
not have had to move at all.

`sample-id1.png` does not have to move: **674 bytes at the full 160 px**, QR
version 26, 0.403 mm a module against the 0.4 floor. The sample document now
prints both symbols at the size a real verification prints them, which is the
whole reason to have a sample. `static/sample-face.png` stays as
`UNFITTABLE_FILE`, because the suite needs a fixture that does not fit and
that is a property of the artwork rather than of what the page shows. It now
holds eight concentric rings instead of the character: the same hard edges,
and the same verdict -- both land at 136 px, at 692 and 698 bytes.

So: **look at documents with the portrait, measure with real captures.** The
drawn face is the stand-in for measuring when the store is empty, reachable
as `?face=drawn` on the sample pages and from `manage.py sample_face`. Two
things it honestly is not: its Laplacian variance at 200 px is 151 against
335-463 for real captures, so its fine detail is tidier than a webcam's; and
it is a little cheap at q30, where `PORTRAIT_QUALITY_LADDER` operates, so a
ladder run against it settles a step or two higher than against a real face.
`debug_sizes` on an instance with real captures remains the measurement of
record.

The drawn face is deterministic (`build(seed=7)`), so two people comparing a
document are comparing the same document.
"""

from __future__ import annotations

import base64

W, H = 640, 480          #: The geometry a real liveness capture comes back at.
CX, CY = 320, 232        #: Head centre.
A, B = 108, 140          #: Head half-width, half-height.

#: What the document carries: a complete data URI, exactly as
#: `_fetch_face_as_data_uri()` hands one back from the upstream.
MEDIA_TYPE = "image/jpeg"
JPEG_QUALITY = 88

#: The portrait the sample person actually shows, under `static/`.
PORTRAIT_FILE = "sample-id1.png"

#: The hard-edged artwork (concentric rings; the cel art before them), kept
#: because the SUITE needs it.
#:
#: "Fits the portrait symbol at no quality at 160 px" is a property of that
#: artwork, not of whatever the sample page shows, and the resolution
#: fallback needs a fixture with that property. Pointing those tests at
#: `data_uri()` tied them to a decision about presentation, so the day the
#: sample became a photograph they would have failed for the wrong reason.
UNFITTABLE_FILE = "sample-face.png"


def _blob(shape, draw, blur=9):
    """A soft-edged alpha mask.

    Nothing here is drawn with a hard edge. A vector edge is what makes a
    cartoon compress unlike a photograph, and a face does not contain one.
    """
    import cv2
    import numpy as np

    m = np.zeros(shape[:2], np.float32)
    draw(m)
    if blur:
        k = blur | 1
        m = cv2.GaussianBlur(m, (k, k), 0)
    return m


def _paint(img, mask, colour):
    import numpy as np

    a = mask[..., None]
    return img * (1 - a) + np.array(colour, np.float32) * a


def _field(rng, scale, blur):
    """Band-limited noise: skin is never one flat tone, and neither is a wall."""
    import cv2

    small = rng.standard_normal((H // scale + 2, W // scale + 2))
    up = cv2.resize(small.astype("float32"), (W, H),
                    interpolation=cv2.INTER_CUBIC)
    return cv2.GaussianBlur(up, (blur | 1, blur | 1), 0)


def build(seed=7):
    """Draw the face. Returns a BGR uint8 array, deterministically."""
    import cv2
    import numpy as np

    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)

    # -- the wall behind, lit from the left --------------------------------
    grad = 148 + 42 * (1 - yy / H) + 26 * (1 - xx / W)
    img = grad[..., None] * np.array([1.04, 1.0, 0.96], np.float32)
    img *= (1 + 0.014 * _field(rng, 60, 81) + 0.018 * _field(rng, 12, 9)
            )[..., None]

    # -- shoulders, collar, neck -------------------------------------------
    shirt = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, H + 26), (258, 146), 0, 0, 360, 1, -1), 21)
    img = _paint(img, shirt * 0.98, (94, 86, 80))
    # Woven cloth, which is most of the frame below the chin.
    img *= (1 + 0.066 * _field(rng, 7, 5) * shirt)[..., None]
    collar = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, H - 6), (78, 54), 0, 180, 360, 1, -1), 21)
    img = _paint(img, collar * 0.55, (150, 152, 156))

    neck = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + B + 22), (62, 86), 0, 0, 360, 1, -1), 15)
    img = _paint(img, neck * 0.95, (116, 144, 176))
    # The jaw throws a shadow down the neck; without it the head floats.
    throat = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + B - 14), (54, 38), 0, 0, 360, 1, -1), 35)
    img *= (1 - 0.20 * throat)[..., None]

    # -- hair behind the head ----------------------------------------------
    hair_back = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY - 40), (A + 18, int(B * 0.92)), 0, 0, 360, 1, -1), 17)
    img = _paint(img, hair_back * 0.97, (38, 42, 52))

    # -- ears, behind the face so the hair covers their tops ---------------
    for sx in (-1, 1):
        ear = _blob(img.shape, lambda m, sx=sx: cv2.ellipse(
            m, (CX + sx * (A - 4), CY + 6), (14, 28), 0, 0, 360, 1, -1), 11)
        img = _paint(img, ear * 0.9, (110, 139, 172))
        inner = _blob(img.shape, lambda m, sx=sx: cv2.ellipse(
            m, (CX + sx * (A - 2), CY + 8), (7, 17), 0, 0, 360, 1, -1), 9)
        img *= (1 - 0.16 * inner)[..., None]

    # -- the face ----------------------------------------------------------
    # Four overlapping ellipses, not one: a head tapers from cranium to
    # chin, and a single oval is the most cartoon-like thing a face can do.
    def head(m):
        for (x, y, rx, ry) in ((CX, CY - 26, A, int(B * 0.74)),
                               (CX, CY + 14, int(A * 0.94), int(B * 0.56)),
                               (CX, CY + 62, int(A * 0.70), int(B * 0.44)),
                               (CX, CY + 100, int(A * 0.36), int(B * 0.22))):
            cv2.ellipse(m, (x, y), (rx, ry), 0, 0, 360, 1, -1)
    face = _blob(img.shape, head, 13)
    img = _paint(img, face * 0.99, (120, 150, 184))

    # -- hair over the crown, with a parting off centre --------------------
    def crown(m):
        cv2.ellipse(m, (CX, CY - 86), (A + 12, 72), 0, 180, 360, 1, -1)
        cv2.ellipse(m, (CX - A - 2, CY - 46), (20, 66), 8, 0, 360, 1, -1)
        cv2.ellipse(m, (CX + A + 2, CY - 46), (20, 66), -8, 0, 360, 1, -1)
        # The fringe: swept, and not symmetrical -- a face that mirrors
        # exactly reads as clip art however well it is shaded.
        cv2.ellipse(m, (CX - 26, CY - 96), (74, 40), -8, 0, 360, 1, -1)
        cv2.ellipse(m, (CX + 46, CY - 104), (52, 32), 12, 0, 360, 1, -1)
    img = _paint(img, _blob(img.shape, crown, 15) * 0.96, (40, 45, 56))

    # -- modelling: one light, up and to the left --------------------------
    img *= (1 + 0.17 * ((1 - yy / H) * 0.6 + (1 - xx / W) * 0.4 - 0.5)
            * 2)[..., None]
    for (x, y, rx, ry, k) in ((CX - 64, CY + 30, 44, 42, -0.09),
                              (CX + 64, CY + 30, 44, 42, -0.11),
                              (CX, CY + B - 30, 72, 42, -0.11),
                              (CX - 6, CY - 92, 82, 40, 0.07),
                              (CX - 40, CY - 16, 40, 34, 0.05)):
        m = _blob(img.shape, lambda mm, c=(x, y), r=(rx, ry):
                  cv2.ellipse(mm, c, r, 0, 0, 360, 1, -1), 41)
        img *= (1 + k * m)[..., None]

    # -- eyes. The right one sits a pixel higher, as everyone's does. ------
    for sx, dy in ((-1, 0), (1, -1)):
        ex, ey = CX + sx * 42, CY - 28 + dy
        socket = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.ellipse(
            m, (ex, ey + 3), (33, 20), 0, 0, 360, 1, -1), 25)
        img *= (1 - 0.11 * socket)[..., None]

        white = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.ellipse(
            m, (ex, ey), (18, 9), 0, 0, 360, 1, -1), 5)
        img = _paint(img, white * 0.88, (168, 176, 184))
        # The upper lid shades the top of the eye; a white oval does not
        # read as an eye.
        shade = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.ellipse(
            m, (ex, ey - 6), (18, 7), 0, 0, 360, 1, -1), 9)
        img *= (1 - 0.30 * shade * white)[..., None]

        iris = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.circle(
            m, (ex, ey + 1), 11, 1, -1), 3)
        img = _paint(img, iris * 0.95, (56, 72, 94))
        pupil = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.circle(
            m, (ex, ey + 1), 5, 1, -1), 3)
        img = _paint(img, pupil * 0.95, (24, 26, 30))
        spark = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.circle(
            m, (ex - 4, ey - 3), 3, 1, -1), 3)
        img = _paint(img, spark * 0.75, (236, 238, 240))

        lash = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.ellipse(
            m, (ex, ey - 4), (19, 8), 0, 180, 360, 1, 3), 3)
        img = _paint(img, lash * 0.6, (58, 66, 84))
        crease = _blob(img.shape, lambda m, ex=ex, ey=ey: cv2.ellipse(
            m, (ex, ey - 9), (20, 10), 0, 180, 360, 1, 2), 7)
        img *= (1 - 0.10 * crease)[..., None]

        brow = _blob(img.shape, lambda m, ex=ex, ey=ey, sx=sx: cv2.ellipse(
            m, (ex + sx * 2, ey - 26), (26, 11), -sx * 4, 190, 350, 1, 8), 11)
        img = _paint(img, brow * 0.78, (44, 50, 62))

    # -- nose ---------------------------------------------------------------
    bridge = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX - 3, CY + 4), (10, 46), 0, 0, 360, 1, -1), 21)
    img *= (1 + 0.11 * bridge)[..., None]
    flank = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX + 13, CY + 10), (8, 40), 0, 0, 360, 1, -1), 19)
    img *= (1 - 0.11 * flank)[..., None]
    tip = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + 40), (17, 12), 0, 0, 360, 1, -1), 15)
    img *= (1 + 0.06 * tip)[..., None]
    under = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + 52), (23, 10), 0, 0, 360, 1, -1), 15)
    img *= (1 - 0.22 * under)[..., None]
    for sx in (-1, 1):
        nostril = _blob(img.shape, lambda m, sx=sx: cv2.ellipse(
            m, (CX + sx * 12, CY + 49), (5, 3), 0, 0, 360, 1, -1), 5)
        img *= (1 - 0.34 * nostril)[..., None]

    # -- mouth --------------------------------------------------------------
    philtrum = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + 62), (5, 9), 0, 0, 360, 1, -1), 9)
    img *= (1 - 0.06 * philtrum)[..., None]
    upper = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + 76), (30, 9), 0, 0, 360, 1, -1), 9)
    img = _paint(img, upper * 0.42, (104, 116, 162))
    lower = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX + 1, CY + 87), (28, 10), 0, 0, 360, 1, -1), 9)
    img = _paint(img, lower * 0.40, (122, 136, 186))
    img *= (1 + 0.07 * _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX + 1, CY + 84), (18, 5), 0, 0, 360, 1, -1), 11))[..., None]
    line = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + 80), (29, 5), 0, 0, 180, 1, 3), 5)
    img = _paint(img, line * 0.62, (70, 76, 104))
    for sx in (-1, 1):
        fold = _blob(img.shape, lambda m, sx=sx: cv2.ellipse(
            m, (CX + sx * 30, CY + 60), (22, 26), -sx * 20, 250, 340, 1, 4), 11)
        img *= (1 - 0.07 * fold)[..., None]
    chin = _blob(img.shape, lambda m: cv2.ellipse(
        m, (CX, CY + 104), (25, 14), 0, 0, 360, 1, -1), 21)
    img *= (1 - 0.05 * chin)[..., None]

    # -- fine structure: what a photograph costs and a drawing does not -----
    skin = np.clip(face + 0.6 * np.clip(neck - face, 0, 1), 0, 1)
    img *= (1 + 0.050 * _field(rng, 22, 29) * skin)[..., None]   # unevenness
    img *= (1 + 0.018 * _field(rng, 14, 11) * skin)[..., None]   # blotching
    img *= (1 + 0.040 * _field(rng, 7, 5) * skin)[..., None]     # texture
    img *= (1 + 0.026 * _field(rng, 4, 3) * skin)[..., None]     # pores
    hairmask = np.clip(hair_back - face, 0, 1)
    img *= (1 + 0.62 * cv2.GaussianBlur(_field(rng, 5, 3), (1, 25), 0)
            * hairmask)[..., None]
    img *= (1 + 0.26 * cv2.GaussianBlur(_field(rng, 2, 1), (1, 13), 0)
            * hairmask)[..., None]

    # -- the sensor ---------------------------------------------------------
    # Blur first, grain after: grain that has been through the lens blur is
    # not grain, and the noise floor of a webcam frame outlasts the
    # downsample to 200 px, which is where the encoder meets it.
    img = cv2.GaussianBlur(img, (3, 3), 0.7)
    img = cv2.addWeighted(img, 1.45, cv2.GaussianBlur(img, (0, 0), 3), -0.45, 0)
    img += rng.standard_normal((H, W, 1)).astype(np.float32) * 4.2   # luma
    img += rng.standard_normal((H, W, 3)).astype(np.float32) * 2.2   # chroma
    return np.clip(img, 0, 255).astype(np.uint8)


def jpeg_bytes(seed=7):
    """The drawn face, encoded as a real capture arrives."""
    import cv2

    ok, buf = cv2.imencode(".jpg", build(seed),
                           [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY])
    if not ok:
        raise RuntimeError("could not encode the sample face")
    return buf.tobytes()


def drawn_data_uri(seed=7):
    """The drawn stand-in as a data URI. See the module docstring for when."""
    return "data:%s;base64,%s" % (
        MEDIA_TYPE, base64.b64encode(jpeg_bytes(seed)).decode("ascii"))


def portrait_jpeg_bytes(name=None):
    """`static/sample-id1.png`, encoded as a capture arrives.

    Re-encoded rather than served as a PNG: every face in this app is a JPEG
    data URI handed back by the liveness iframe, and a sample that travelled
    as something else would be exercising a path that does not exist.

    `name` is for the suite, which needs the unfittable artwork by its own name.
    """
    import cv2
    import numpy as np

    from django.conf import settings

    path = settings.BASE_DIR / "static" / (name or PORTRAIT_FILE)
    img = cv2.imdecode(np.fromfile(str(path), np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise RuntimeError("could not read %s" % path)
    ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY,
                                         JPEG_QUALITY])
    if not ok:
        raise RuntimeError("could not encode the sample portrait")
    return buf.tobytes()


def unfittable_data_uri():
    """The unfittable artwork, as a data URI. A fixture, never what a page shows.

    See `UNFITTABLE_FILE`: what the suite wants from it is that it fits the
    portrait symbol at no quality at 160 px, which the photograph the sample
    now shows does not do.
    """
    return "data:%s;base64,%s" % (
        MEDIA_TYPE,
        base64.b64encode(portrait_jpeg_bytes(UNFITTABLE_FILE)).decode("ascii"))


def data_uri(drawn=False):
    """`data:image/jpeg;base64,...` -- the shape every face in this app has.

    The chosen portrait by default, the drawn stand-in with `drawn=True`. The
    document, the credential's portrait symbol and the demo redaction all take
    a complete data URI, so the sample person carries one too and travels
    every path a real capture does.
    """
    if drawn:
        return drawn_data_uri()
    return "data:%s;base64,%s" % (
        MEDIA_TYPE, base64.b64encode(portrait_jpeg_bytes()).decode("ascii"))

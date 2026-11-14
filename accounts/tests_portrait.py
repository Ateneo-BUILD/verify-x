"""The face in the portrait symbol: cropped to the head, and AVIF when asked.

Measured on `static/sample-id1.png` (an ID photograph with shoulders), the
drawn sample face, and a stand-in cut from the photograph to the framing of
a real eVerify capture (127 x 170, the face 66% of the width). Face quality
here is SSIM over the FACE BOX only, resampled to 128 x 128, so a cropped
and an uncropped render are judged on the same pixels -- the ones a
verifier compares against the person.
"""

import base64
import hashlib
import io
import unittest
import uuid
from unittest import mock

import cv2
import numpy as np
from django.test import SimpleTestCase, override_settings

from accounts import credentials, portrait_avif, sample_face
from accounts.debug_store import _ssim


def _image(uri):
    raw = base64.b64decode(uri.split(",", 1)[1])
    return cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)


def _uri(image, ext=".png"):
    ok, buf = cv2.imencode(ext, image)
    assert ok
    return "data:image/%s;base64,%s" % (ext[1:], base64.b64encode(bytes(buf)).decode())


def _tight_framing():
    """The photograph cut to a real capture's framing: 127 x 170, the
    face 66% wide."""
    image = _image(sample_face.data_uri())
    fx, fy, fw, _ = credentials.face_box(image)
    s = 84.0 / fw
    x0, y0 = int(round(fx + fw / 2 - 63.5 / s)), int(round(fy - 37 / s))
    w, h = int(round(127 / s)), int(round(170 / s))
    crop = image[max(0, y0):y0 + h, max(0, x0):x0 + w]
    return _uri(cv2.resize(crop, (127, 170), interpolation=cv2.INTER_AREA), ".jpg")


def _face_score(uri, blob, region):
    """SSIM of the face box between the source and the decoded portrait,
    which covers `region` of the source."""
    source = cv2.cvtColor(_image(uri), cv2.COLOR_BGR2GRAY)
    fx, fy, fw, fh = credentials.face_box(source)
    ref = cv2.resize(source[int(fy):int(fy + fh), int(fx):int(fx + fw)],
                     (128, 128), interpolation=cv2.INTER_AREA)
    back = credentials.decode_portrait(blob)
    x0, y0, cw, ch = region
    sx, sy = back.shape[1] / cw, back.shape[0] / ch
    ax, ay = fw * sx / 128, fh * sy / 128
    m = np.float32([[ax, 0, (fx - x0) * sx + 0.5 * ax - 0.5],
                    [0, ay, (fy - y0) * sy + 0.5 * ay - 0.5]])
    sample = cv2.warpAffine(back, m, (128, 128),
                            flags=cv2.INTER_CUBIC | cv2.WARP_INVERSE_MAP,
                            borderMode=cv2.BORDER_REPLICATE)
    return _ssim(sample, ref)


def _whole(image):
    height, width = image.shape[:2]
    return (0, 0, width, height)


class HeadCropTest(SimpleTestCase):

    def test_an_id_photo_is_cropped_to_the_head(self):
        """The photograph is 1,254 px with the face 43% of the width: most of
        what the symbol paid for was shoulders and background."""
        image = _image(sample_face.data_uri())
        x, y, w, h = credentials.portrait_frame(image)
        fx, fy, fw, fh = credentials.face_box(image)
        self.assertEqual(w, h)
        self.assertAlmostEqual(w, credentials.PORTRAIT_HEAD_SCALE * fw, delta=2)
        self.assertLess(w, image.shape[1] * 0.75)

    def test_the_chin_is_never_cut(self):
        """Squaring a portrait off is how somebody's chin goes, so the head
        box keeps room under the face and over it on every face measured."""
        for uri in (sample_face.data_uri(), sample_face.data_uri(drawn=True),
                    _tight_framing()):
            image = _image(uri)
            x, y, side, _ = credentials.portrait_frame(image)
            fx, fy, fw, fh = credentials.face_box(image)
            self.assertGreaterEqual((y + side) - (fy + fh), 0.15 * fh)
            # The lift: the hairline is part of what a person compares.
            self.assertGreaterEqual(fy - y, 0.28 * fh)
            self.assertLessEqual(x, fx)
            self.assertGreaterEqual(x + side, fx + fw)

    def test_a_small_face_in_a_big_picture_is_not_what_it_crops_to(self):
        """A face a fifth of the picture's width is a badge or a poster, not
        the subject of an ID portrait."""
        drawn = _image(sample_face.data_uri(drawn=True))
        fw = credentials.face_box(drawn)[2]
        scale = 0.18 * 900 / fw
        small = cv2.resize(drawn, None, fx=scale, fy=scale,
                           interpolation=cv2.INTER_AREA)
        canvas = np.full((900, 900, 3), 235, np.uint8)
        canvas[300:300 + small.shape[0], 300:300 + small.shape[1]] = small
        self.assertEqual(credentials.portrait_frame(canvas), _whole(canvas))

    def test_a_face_that_already_fills_the_picture_keeps_nearly_all_of_it(self):
        """eVerify's own portraits are framed on the face, so the crop takes
        the top and bottom off and little else -- it costs them nothing."""
        image = _image(_tight_framing())
        x, y, w, h = credentials.portrait_frame(image)
        self.assertGreaterEqual(w, 0.95 * image.shape[1])

    def test_no_face_means_no_crop(self):
        """Whatever cannot be found is drawn whole."""
        noise = np.random.default_rng(3).integers(0, 255, (320, 480, 3),
                                                  dtype=np.uint8)
        self.assertEqual(credentials.portrait_frame(noise), _whole(noise))
        blob = credentials.render_portrait(_uri(noise), fmt="webp")
        self.assertEqual(credentials.decode_portrait(blob).shape, (107, 160))

    def test_the_portrait_is_the_square_around_the_head(self):
        """The drawn face is 640 x 480; drawn whole it would be 160 x 120."""
        blob = credentials.render_portrait(sample_face.data_uri(drawn=True),
                                           fmt="webp")
        self.assertEqual(credentials.decode_portrait(blob).shape, (160, 160))

    def test_the_crop_buys_face_detail_at_the_same_bytes(self):
        """+0.036 on the photograph through this renderer; pinned at +0.03."""
        uri = sample_face.data_uri()
        image = _image(uri)
        cropped = credentials.render_portrait(uri, fmt="webp")
        with mock.patch.object(credentials, "portrait_frame", _whole):
            whole = credentials.render_portrait(uri, fmt="webp")
        self.assertGreater(
            _face_score(uri, cropped, credentials.portrait_frame(image)),
            _face_score(uri, whole, _whole(image)) + 0.03)

    def test_a_detector_that_fails_costs_the_crop_and_not_the_face(self):
        with mock.patch.object(credentials, "_face_detector",
                               side_effect=RuntimeError("no cascade")):
            image = _image(sample_face.data_uri())
            # Each layer on its own: face_box answers None rather than
            # raising, and the frame is the whole picture.
            self.assertIsNone(credentials.face_box(image))
            self.assertEqual(credentials.portrait_frame(image), _whole(image))
            self.assertIsNotNone(
                credentials.render_portrait(sample_face.data_uri(), fmt="webp"))

    def test_the_size_report_scores_the_frame_it_keeps(self):
        """`measure_portrait` scores the frame the symbol keeps, not the whole
        upload: stretched over the upload, it would score the crop, not the
        encoding."""
        from accounts.debug_store import measure_portrait

        out = measure_portrait(sample_face.data_uri())
        self.assertGreater(out["ssim"], 0.65)


@unittest.skipUnless(portrait_avif.available(), "Pillow without AVIF support")
class AvifPortraitTest(SimpleTestCase):

    #: The container for a 160 x 160 face whose av1C is 81 00 1c 00 and
    #: whose image data is 00 01 02 -- the vector the apps rebuild against.
    GOLDEN = bytes.fromhex(
        "0000001c667479706176696600000000617669666d6966316d696166000000e96d65"
        "7461000000000000002168646c72000000000000000070696374000000000000000000"
        "000000000000000e7069746d0000000000010000001e696c6f63000000004400000100"
        "01000000010000010d000000030000002869696e660000000000010000001a696e6665"
        "020000000001000061763031436f6c6f72000000006869707270000000496970636f00"
        "0000146973706500000000000000a0000000a00000000e706978690000000001080000"
        "000c6176314381001c0000000013636f6c726e636c780001000d000680000000176970"
        "6d610000000000000001000104010283040000000b6d646174000102")

    def _gray(self):
        return cv2.cvtColor(cv2.resize(_image(sample_face.data_uri()),
                                       (160, 160)), cv2.COLOR_BGR2GRAY)

    def test_the_container_is_the_specified_bytes(self):
        """Every byte is fixed but the four values, and the image data always
        starts at 269. This is the specification both apps build to."""
        built = portrait_avif.container(160, 160, b"\x81\x00\x1c\x00",
                                        b"\x00\x01\x02")
        self.assertEqual(built, self.GOLDEN)
        self.assertEqual(portrait_avif.CONTAINER_BYTES, 269)
        compact = portrait_avif.HEADER.pack(160, 160, b"\x81\x00\x1c\x00") \
            + b"\x00\x01\x02"
        self.assertEqual(portrait_avif.expand(compact), self.GOLDEN)

    def test_the_container_decodes_to_what_the_encoder_meant(self):
        """The encoder's own file is thrown away; ours must be the same
        picture, pixel for pixel."""
        from PIL import Image

        gray = self._gray()
        for quality in (5, 30, 60):
            compact = portrait_avif.encode(gray, quality)
            own = io.BytesIO()
            Image.fromarray(gray, "L").save(own, "AVIF", quality=quality,
                                            speed=portrait_avif.SPEED)
            with Image.open(io.BytesIO(own.getvalue())) as theirs:
                expected = np.array(theirs.convert("L"))
            np.testing.assert_array_equal(portrait_avif.decode(compact),
                                          expected)
            # And the symbol saves exactly the container.
            self.assertEqual(len(own.getvalue()) - len(compact),
                             portrait_avif.CONTAINER_BYTES
                             - portrait_avif.HEADER.size)

    def test_only_a_monochrome_8_bit_still_is_accepted(self):
        from PIL import Image

        colour = io.BytesIO()
        Image.new("RGB", (32, 32), (200, 40, 40)).save(colour, "AVIF")
        with self.assertRaises(ValueError):
            portrait_avif._parse(colour.getvalue())

    def test_an_avif_portrait_rides_its_own_marker(self):
        blob = credentials.render_portrait(sample_face.data_uri(), fmt="avif")
        self.assertTrue(credentials.is_avif_portrait(blob))
        self.assertTrue(credentials.portrait_fits(blob))
        text = credentials.portrait_qr(blob, credential_id=uuid.uuid4())
        self.assertTrue(text.startswith("CL03F2:"))
        self.assertEqual(credentials.decode_portrait(blob).shape, (160, 160))

    def test_a_fake_blob_is_never_taken_for_avif(self):
        """Anything that is not plainly the compact form is WebP, which is
        what every portrait was -- including the stand-ins tests pass."""
        self.assertFalse(credentials.is_avif_portrait(b"pretend this is a webp"))
        webp = credentials.render_portrait(sample_face.data_uri(), fmt="webp")
        self.assertFalse(credentials.is_avif_portrait(webp))
        self.assertTrue(credentials.portrait_qr(
            webp, credential_id=uuid.uuid4()).startswith("CL03F1:"))

    def test_avif_is_sharper_than_webp_in_the_same_symbol(self):
        """+0.05 to +0.06 through this renderer on both faces; pinned at +0.02."""
        for uri in (sample_face.data_uri(), _tight_framing()):
            region = credentials.portrait_frame(_image(uri))
            avif = credentials.render_portrait(uri, fmt="avif")
            webp = credentials.render_portrait(uri, fmt="webp")
            self.assertGreater(_face_score(uri, avif, region),
                               _face_score(uri, webp, region) + 0.02)

    def test_the_setting_chooses_the_encoder(self):
        uri = sample_face.data_uri()
        with override_settings(PORTRAIT_FORMAT="avif"):
            self.assertTrue(credentials.is_avif_portrait(
                credentials.render_portrait(uri)))
        for value in ("webp", "WEBP", "gif", ""):
            with override_settings(PORTRAIT_FORMAT=value):
                self.assertFalse(credentials.is_avif_portrait(
                    credentials.render_portrait(uri)), value)

    def test_the_encoder_is_a_declared_dependency(self):
        """Declared, because an undeclared dependency passes tests wherever it
        happens to be installed while a deployment returns no face. 11.2 is
        the first release whose wheels carry libavif."""
        import re

        from django.conf import settings

        text = (settings.BASE_DIR / "requirements.txt").read_text()
        found = re.search(r"^Pillow>=(\d+)\.(\d+)", text, re.M)
        self.assertIsNotNone(found, "Pillow is not in requirements.txt")
        self.assertGreaterEqual((int(found[1]), int(found[2])), (11, 2))

    def test_it_ships_switched_off(self):
        """Off by default: a reader that knows only CL03F1 shows no face for
        a CL03F2 document."""
        from django.conf import settings

        self.assertEqual(credentials.portrait_format(), "webp")
        self.assertEqual(settings.PORTRAIT_FORMAT, "webp")

    def test_no_avif_encoder_costs_the_codec_and_not_the_face(self):
        uri = sample_face.data_uri()
        with mock.patch.object(portrait_avif, "available", return_value=False):
            blob = credentials.render_portrait(uri, fmt="avif")
        self.assertFalse(credentials.is_avif_portrait(blob))
        with mock.patch.object(portrait_avif, "encode",
                               side_effect=OSError("encoder crashed")):
            blob = credentials.render_portrait(uri, fmt="avif")
        self.assertIsNotNone(blob)
        self.assertFalse(credentials.is_avif_portrait(blob))

    def test_a_container_that_does_not_decode_is_never_sent(self):
        """The symbol carries OUR container's contents, so the server proves
        that container opens before a phone is asked to."""
        with mock.patch.object(portrait_avif, "decode",
                               side_effect=ValueError("bad container")):
            blob = credentials.render_portrait(sample_face.data_uri(),
                                               fmt="avif")
        self.assertIsNotNone(blob)
        self.assertFalse(credentials.is_avif_portrait(blob))

    def test_the_card_face_is_a_file_a_browser_opens(self):
        """The compact form is for the symbol; the card draws a real AVIF of
        the SAME picture, not a second render."""
        from PIL import Image

        blob = credentials.render_portrait(sample_face.data_uri(), fmt="avif")
        uri = credentials.portrait_data_uri(blob)
        self.assertTrue(uri.startswith("data:image/avif;base64,"))
        raw = base64.b64decode(uri.split(",", 1)[1])
        self.assertEqual(raw, portrait_avif.expand(blob))
        with Image.open(io.BytesIO(raw)) as drawn:
            np.testing.assert_array_equal(np.array(drawn.convert("L")),
                                          credentials.decode_portrait(blob))
        webp = credentials.render_portrait(sample_face.data_uri(), fmt="webp")
        self.assertEqual(credentials.portrait_data_uri(webp),
                         "data:image/webp;base64,"
                         + base64.b64encode(webp).decode())

    def test_the_hash_binds_the_bytes_the_symbol_carries(self):
        """`portrait_hash` covers the compact bytes -- what a phone scans --
        not the container it rebuilds around them."""
        from ovcrypto import base45

        blob = credentials.render_portrait(sample_face.data_uri(), fmt="avif")
        text = credentials.portrait_qr(blob, credential_id=uuid.uuid4())
        # The symbol's tail is exactly the bytes `build_claims(portrait=...)`
        # hashes (pinned in CredentialContentTest) -- no container in it.
        self.assertEqual(base45.decode(text.split(":", 2)[2]), blob)
        self.assertNotIn(b"ftyp", blob)
        self.assertEqual(len(blob), len(portrait_avif.expand(blob))
                         - portrait_avif.CONTAINER_BYTES
                         + portrait_avif.HEADER.size)

    def test_demo_mode_still_resamples_the_face_away(self):
        """Redaction happens before the encoder is chosen. A face already
        reduced to the 10 x 10 grid is barely changed by being reduced
        again."""
        blob = credentials.render_portrait(sample_face.data_uri(), fmt="avif",
                                           redact=True)
        back = credentials.decode_portrait(blob).astype(np.float64)
        grid = cv2.resize(back, (credentials.PORTRAIT_REDACT_PX,) * 2,
                          interpolation=cv2.INTER_AREA)
        again = cv2.resize(grid, (back.shape[1], back.shape[0]),
                           interpolation=cv2.INTER_CUBIC)
        self.assertLess(float(np.abs(back - again).mean()), 8.0)

    def test_a_holder_symbol_in_either_marker_is_proved_the_same_way(self):
        from types import SimpleNamespace

        from accounts import holders
        from ovcrypto import wire

        blob = credentials.render_portrait(sample_face.data_uri(), fmt="avif")
        credential_id = uuid.uuid4()
        opened = SimpleNamespace(restricted_claims={
            wire.T_PORTRAIT_HASH: hashlib.sha256(blob).digest()})
        text = credentials.portrait_qr(blob, credential_id=credential_id)
        self.assertEqual(holders._bound_face(opened, credential_id, text), blob)
        with self.assertRaises(Exception):
            holders._bound_face(opened, credential_id,
                                "CL03F3:" + text.split(":", 1)[1])


class PortraitSearchTest(SimpleTestCase):
    """The WebP quality is searched, not walked, and the answer is the walk's.

    Walking PORTRAIT_QUALITY_LADDER from 95 down takes about 95 encodes at
    1.44 ms before the sample photograph fits, most of what logging a
    verification costs. Bisection finds the boundary in about seven; the look
    PORTRAIT_WEBP_PROBE steps above it is what makes the answer the walk's,
    because WebP's size is not monotone in quality. Across 816 cases (48
    pictures at every rung from 80 to 208 px) bisection alone matched the
    walk 810 times and settled at most 2 steps low; with the probe, 816.

    The algorithm is pinned on a fake encoder whose size curve is chosen, so
    the dips are where the test says they are on any machine. The real
    encoder is then held to the walk's answer on the same machine.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # The largest image the symbol carries: fits() depends on length only.
        low, high = 1, 4000
        while low < high:
            mid = (low + high + 1) // 2
            if credentials.portrait_fits(b"\x00" * mid):
                low = mid
            else:
                high = mid - 1
        cls.T = low

    def _search(self, size, probe=None):
        """`_fit_webp` against an encoder whose output at quality q is
        size(q) bytes. Returns (quality found or None, encodes made)."""
        calls = []

        def imencode(ext, image, params):
            q = params[1]
            calls.append(q)
            return True, np.frombuffer(bytes([q]) * size(q), np.uint8)

        patches = [mock.patch("cv2.imencode", side_effect=imencode)]
        if probe is not None:
            patches.append(mock.patch.object(credentials, "PORTRAIT_WEBP_PROBE", probe))
        with patches[0]:
            if probe is not None:
                with patches[1]:
                    blob = credentials._fit_webp(np.zeros((8, 8), np.uint8))
            else:
                blob = credentials._fit_webp(np.zeros((8, 8), np.uint8))
        return (blob[0] if blob else None), len(set(calls))

    def test_a_monotone_curve_is_found_in_a_handful_of_encodes(self):
        found, encodes = self._search(lambda q: self.T - 40 + q)
        self.assertEqual(found, 40)
        self.assertLessEqual(encodes, 7 + credentials.PORTRAIT_WEBP_PROBE + 1)

    # With the boundary at 40, bisection over 1..95 visits 48, 24, 36, 42,
    # 39, 40 and 41. The dips below sit where it never looks, so only the
    # look upward can find them.

    def test_a_dip_just_above_the_boundary_is_found(self):
        """41 and 42 do not fit and 43 does: the walk takes 43, so must this."""
        size = lambda q: self.T if q == 43 else self.T - 40 + q
        self.assertEqual(self._search(size)[0], 43)
        # And it is the look upward that finds it, not luck in the bisection.
        self.assertEqual(self._search(size, probe=0)[0], 40)

    def test_a_dip_above_a_dip_is_followed(self):
        """Each fit found moves the window up with it, as the walk would: 43
        is inside the first window and 47 only inside the one 43 opens."""
        dips = {43, 47}
        size = lambda q: self.T if q in dips else self.T - 40 + q
        self.assertEqual(self._search(size, probe=4)[0], 47)

    def test_a_dip_at_the_bottom_is_found_when_bisection_finds_nothing(self):
        """Quality 1 does not fit and 2 does. Bisection reports nothing; the
        look upward starts from the bottom, so None still means none fits."""
        size = lambda q: self.T if q == 2 else self.T + q
        self.assertEqual(self._search(size)[0], 2)

    def test_none_still_means_no_quality_fits(self):
        found, encodes = self._search(lambda q: self.T + q)
        self.assertIsNone(found)
        self.assertLessEqual(encodes, 7 + credentials.PORTRAIT_WEBP_PROBE + 1)

    def test_a_face_that_fits_everywhere_gets_the_top_quality(self):
        self.assertEqual(self._search(lambda q: self.T - 100)[0],
                         max(credentials.PORTRAIT_QUALITY_LADDER))

    @staticmethod
    def _walk(gray):
        """The walk the search must agree with: every rung from the top."""
        for q in credentials.PORTRAIT_QUALITY_LADDER:
            ok, buf = cv2.imencode(".webp", gray, [int(cv2.IMWRITE_WEBP_QUALITY), q])
            if ok and credentials.portrait_fits(bytes(buf)):
                return bytes(buf)
        return None

    @staticmethod
    def _prepared(image, px):
        x, y, w, h = credentials.portrait_frame(image)
        image = image[y:y + h, x:x + w]
        s = min(px / w, px / h)
        image = cv2.resize(image, (max(1, int(round(w * s))), max(1, int(round(h * s)))),
                           interpolation=cv2.INTER_AREA)
        return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    def test_on_real_pictures_it_returns_what_the_walk_returned(self):
        photo = _image(sample_face.data_uri())
        contrast = np.clip((photo.astype(np.float32) - 128) * 1.3 + 128, 0, 255).astype(np.uint8)
        noise = np.random.default_rng(3).integers(0, 255, (360, 300, 3), dtype=np.uint8)
        pictures = {"photo": photo, "contrast": contrast,
                    "drawn": sample_face.build(seed=6), "noise": noise}
        for name, image in pictures.items():
            for px in (160, 112, 88, 80):
                with self.subTest(picture=name, px=px):
                    gray = self._prepared(image, px)
                    self.assertEqual(credentials._fit_webp(gray), self._walk(gray))

    def test_the_sample_photograph_takes_a_dozen_encodes_not_ninety(self):
        real = cv2.imencode
        with mock.patch("cv2.imencode", side_effect=real) as spy:
            blob = credentials.render_portrait(sample_face.data_uri(), fmt="webp")
        self.assertIsNotNone(blob)
        self.assertLessEqual(spy.call_count, 15)

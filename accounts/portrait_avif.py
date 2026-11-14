"""The portrait as AVIF, small enough to ride a QR.

An AVIF file is a 269-byte container wrapped around the picture: a dozen ISO
boxes saying what kind of image this is, how big, and where its bytes start.
At the portrait symbol's 701-byte budget that container would cost more than a
third of the face, so the symbol carries only what varies and both ends wrap
the same fixed container around it.

What an `CL03F2:` symbol carries, after base45:

    u16 width | u16 height | av1C (4 bytes) | AV1 image data

The container is `container()` below, byte for byte, and it is the
specification: the verifier app and the holder app build exactly these bytes
around what they scanned and hand the result to the platform's own AVIF
decoder. Nothing about it comes from whichever libavif encoded the face --
the encoder's own file is parsed for the four values and thrown away -- so a
server on one libavif and a phone on another agree for as long as both keep
to this function.

It is libavif's own layout (as of 1.3 and 1.4) for a monochrome 8-bit still,
which is why every box has a fixed size and the image data always starts at
byte 269.

**Monochrome, 8-bit, one item, and nothing else.** That is all a portrait ever
is here, and a container that admitted alpha, colour or a grid would be
somewhere for an encoder change to slip a picture the apps cannot rebuild.
`encode()` refuses anything else, and the caller falls back to WebP.

Pillow, not cv2, because the opencv-python wheels are built without an AVIF
encoder (the constants are there; `imencode('.avif')` finds no codec). Pillow
11.2 and later ship libavif with aom to encode and dav1d to decode, on Linux
and Windows alike.
"""

from __future__ import annotations

import io
import struct

#: u16 width, u16 height, the 4-byte AV1 codec configuration.
HEADER = struct.Struct(">HH4s")

#: Bytes of container in front of the image data, always.
CONTAINER_BYTES = 269

#: libavif's speed, 0 (slowest, smallest) to 10. Measured at 160 px on a
#: face: 6 is 13 ms an encode against 48 at 4 and 117 at 2, for about 3% more
#: bytes than 4. A quality search runs ten or so, on the verification path.
SPEED = 6


def available():
    """Can this deployment encode AVIF at all? Never raises."""
    try:
        from PIL import features

        return bool(features.check("avif"))
    except Exception:
        return False


def _box(kind, body):
    return struct.pack(">I4s", 8 + len(body), kind) + body


def _full_box(kind, version, flags, body):
    return _box(kind, struct.pack(">I", (version << 24) | flags) + body)


def container(width, height, av1c, data):
    """A complete AVIF file: the fixed container around `data`."""
    if not (0 < width < 65536 and 0 < height < 65536):
        raise ValueError("portrait dimensions out of range")
    if len(av1c) != 4 or not data:
        raise ValueError("not an AV1 portrait")
    ispe = _full_box(b"ispe", 0, 0, struct.pack(">II", width, height))
    pixi = _full_box(b"pixi", 0, 0, bytes([1, 8]))         # one 8-bit channel
    av1c_box = _box(b"av1C", bytes(av1c))
    # BT.709 primaries, sRGB transfer, BT.601 matrix, full range -- what
    # libavif writes for a grayscale still.
    colr = _box(b"colr", b"nclx" + struct.pack(">HHH", 1, 13, 6) + b"\x80")
    ipco = _box(b"ipco", ispe + pixi + av1c_box + colr)
    # Item 1 has four properties; only av1C is essential (0x80).
    ipma = _full_box(b"ipma", 0, 0, struct.pack(">IHB", 1, 1, 4)
                     + bytes([0x01, 0x02, 0x83, 0x04]))
    infe = _full_box(b"infe", 2, 0,
                     struct.pack(">HH", 1, 0) + b"av01" + b"Color\0")
    meta = _full_box(b"meta", 0, 0, b"".join([
        _full_box(b"hdlr", 0, 0, b"\0" * 4 + b"pict" + b"\0" * 13),
        _full_box(b"pitm", 0, 0, struct.pack(">H", 1)),
        # 4-byte offsets and lengths, no base offset; one item, one extent.
        _full_box(b"iloc", 0, 0, bytes([0x44, 0x00]) + struct.pack(
            ">HHHHII", 1, 1, 0, 1, CONTAINER_BYTES, len(data))),
        _full_box(b"iinf", 0, 0, struct.pack(">H", 1) + infe),
        _box(b"iprp", ipco + ipma),
    ]))
    ftyp = _box(b"ftyp", b"avif" + b"\0\0\0\0" + b"avif" + b"mif1" + b"miaf")
    head = ftyp + meta + struct.pack(">I4s", 8 + len(data), b"mdat")
    assert len(head) == CONTAINER_BYTES, len(head)
    return head + bytes(data)


def expand(compact):
    """The `CL03F2:` image bytes -> a complete AVIF file. Raises ValueError."""
    compact = bytes(compact)
    if len(compact) <= HEADER.size:
        raise ValueError("not an AVIF portrait")
    width, height, av1c = HEADER.unpack_from(compact)
    return container(width, height, av1c, compact[HEADER.size:])


def _children(data, start, end):
    while start + 8 <= end:
        size, kind = struct.unpack_from(">I4s", data, start)
        if size < 8 or start + size > end:
            raise ValueError("malformed box")
        yield kind, start, start + size
        start += size


def _parse(raw):
    """Pull the four values out of an encoder's own AVIF file."""
    found = {}
    for kind, start, end in _children(raw, 0, len(raw)):
        if kind != b"meta":
            continue
        for kind2, s2, e2 in _children(raw, start + 12, end):
            if kind2 == b"iloc":
                version = raw[s2 + 8]
                sizes, base = raw[s2 + 12], raw[s2 + 13]
                off_size, len_size, base_size = sizes >> 4, sizes & 15, base >> 4
                if version != 0 or (off_size, len_size, base_size) != (4, 4, 0):
                    raise ValueError("unexpected iloc layout")
                count, item, _ref, extents, offset, length = struct.unpack_from(
                    ">HHHHII", raw, s2 + 14)
                if (count, item, extents) != (1, 1, 1):
                    raise ValueError("more than one item or extent")
                found["data"] = raw[offset:offset + length]
            elif kind2 == b"iprp":
                for kind3, s3, e3 in _children(raw, s2 + 8, e2):
                    if kind3 != b"ipco":
                        continue
                    for kind4, s4, e4 in _children(raw, s3 + 8, e3):
                        if kind4 == b"ispe":
                            found["size"] = struct.unpack_from(">II", raw, s4 + 12)
                        elif kind4 == b"pixi":
                            found["pixi"] = bytes(raw[s4 + 12:e4])
                        elif kind4 == b"av1C":
                            found["av1c"] = bytes(raw[s4 + 8:s4 + 12])
    if set(found) != {"data", "size", "pixi", "av1c"}:
        raise ValueError("missing %s" % sorted({"data", "size", "pixi", "av1c"} - set(found)))
    if found["pixi"] != bytes([1, 8]):
        raise ValueError("not a monochrome 8-bit image")
    if not found["av1c"][2] & 0x10:
        raise ValueError("AV1 stream is not monochrome")
    return found


def encode(gray, quality):
    """A 2-D uint8 array -> `CL03F2:` image bytes. Raises on anything else."""
    from PIL import Image

    out = io.BytesIO()
    Image.fromarray(gray, "L").save(out, "AVIF", quality=int(quality),
                                    speed=SPEED)
    found = _parse(out.getvalue())
    width, height = found["size"]
    return HEADER.pack(width, height, found["av1c"]) + found["data"]


def decode(compact):
    """`CL03F2:` image bytes -> a 2-D uint8 array, through the fixed container."""
    import numpy as np
    from PIL import Image

    with Image.open(io.BytesIO(expand(compact))) as image:
        return np.array(image.convert("L"))

"""Base45 encoding (RFC 9285).

Chosen over byte-mode QR because nothing in the surrounding stack handles binary:
`qrcode` generators take strings, and OpenCV / jsQR / ZXing decoders all return
`str`.  On iOS, `AVCaptureMetadataOutput.stringValue` cannot carry non-UTF-8 bytes
at all.  Base45 maps 2 bytes -> 3 characters drawn from the QR *alphanumeric*
charset, which QR packs at 11 bits per 2 characters -- about 3% overhead against
byte mode, versus 33% for Base64.
"""

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

_DECODE = {c: i for i, c in enumerate(ALPHABET)}


class Base45Error(ValueError):
    """Raised when a string is not valid Base45."""


def encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data) - 1, 2):
        x = (data[i] << 8) + data[i + 1]
        x, c = divmod(x, 45)
        a, b = divmod(x, 45)
        out.append(ALPHABET[c] + ALPHABET[b] + ALPHABET[a])
    if len(data) % 2:
        b, a = divmod(data[-1], 45)
        out.append(ALPHABET[a] + ALPHABET[b])
    return "".join(out)


def decode(text: str) -> bytes:
    try:
        vals = [_DECODE[c] for c in text]
    except KeyError as exc:
        raise Base45Error(f"invalid base45 character: {exc.args[0]!r}") from None

    if len(vals) % 3 == 1:
        raise Base45Error("invalid base45 length (mod 3 == 1)")

    out = bytearray()
    for i in range(0, len(vals) - 2, 3):
        x = vals[i] + vals[i + 1] * 45 + vals[i + 2] * 45 * 45
        if x > 0xFFFF:
            raise Base45Error("base45 triplet out of range")
        out += x.to_bytes(2, "big")
    if len(vals) % 3 == 2:
        x = vals[-2] + vals[-1] * 45
        if x > 0xFF:
            raise Base45Error("base45 pair out of range")
        out.append(x)
    return bytes(out)

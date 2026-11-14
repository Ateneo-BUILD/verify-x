"""QR version selection and physical sizing for the printed stamp.

The binding constraint on payload size is physical, not capacity. A payload that
"fits in a QR code" can still be unscannable: a high version packs more modules
into the same printed square, and below roughly 0.4 mm per module a laser print
photographed under field lighting starts failing.

So the print system should size the stamp from this module, not from a fixed
version -- and the size test asserts millimetres per module, not "it fits".
"""

from __future__ import annotations

# Alphanumeric-mode character capacity by version, for the two error-correction
# levels worth using on a document stamp. Level Q (25% recovery) tolerates a
# stamped, folded or partly smudged page; level M (15%) buys ~15% more room.
CAPACITY_ALNUM = {
    "M": [20, 38, 61, 90, 122, 154, 178, 221, 262, 311, 366, 419, 483, 528,
          600, 656, 734, 816, 909, 970, 1035, 1134, 1248, 1326, 1451, 1542,
          1637, 1732, 1839, 1994, 2113, 2238, 2369, 2506, 2632, 2780, 2894,
          3054, 3220, 3391],
    # Derived by binary search against a standards encoder, not retyped. A
    # value too generous from v23 up (v40 holds 2420, not 2566) would make
    # `version_for` return a version too low and size the stamp for fewer
    # modules than the symbol has: a print BELOW the 0.4 mm floor this
    # module exists to enforce, which is the one failure it must not have.
    "Q": [16, 29, 47, 67, 87, 108, 125, 157, 189, 221, 259, 296, 352, 376,
          426, 470, 531, 574, 644, 702, 742, 823, 890, 963, 1041, 1094, 1172,
          1263, 1322, 1429, 1499, 1618, 1700, 1787, 1867, 1966, 2071, 2181,
          2298, 2420],
}

# Below this, capture off a printed page becomes unreliable.
MIN_MODULE_MM = 0.4


class TooLarge(ValueError):
    pass


def modules(version: int) -> int:
    return 17 + 4 * version


def version_for(char_count: int, ec_level: str = "Q") -> int:
    """Smallest QR version holding ``char_count`` alphanumeric characters."""
    try:
        table = CAPACITY_ALNUM[ec_level]
    except KeyError:
        raise ValueError("ec_level must be M or Q") from None
    for i, capacity in enumerate(table, start=1):
        if char_count <= capacity:
            return i
    raise TooLarge("%d characters exceeds QR capacity at level %s"
                   % (char_count, ec_level))


def module_mm(version: int, stamp_mm: float) -> float:
    return stamp_mm / modules(version)


def plan(char_count: int, stamp_mm: float = 40.0, ec_level: str = "Q") -> dict:
    """Full sizing decision for a payload, for the print system and for tests."""
    version = version_for(char_count, ec_level)
    mm = module_mm(version, stamp_mm)
    return {
        "chars": char_count,
        "ec_level": ec_level,
        "version": version,
        "modules": modules(version),
        "stamp_mm": stamp_mm,
        "module_mm": mm,
        "scannable": mm >= MIN_MODULE_MM,
        "min_stamp_mm": modules(version) * MIN_MODULE_MM,
    }

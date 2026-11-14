# -*- coding: utf-8 -*-
"""Single source of truth for the verify version and build number.

    python version.py                 print the current stamp
    python version.py --bump-build    advance BUILD by one, re-date it
    python version.py --set 1.6       start a new version (BUILD keeps
                                      climbing; it never resets)

The VERSION file next to this module holds three fields:

    VERSION   the released version, matching the git tag "Version<X.Y>"
    BUILD     a sequential counter, zero-padded to five digits: 00001,
              00002, ... It counts builds, not commits, so it advances
              only when a build is actually cut
    DATE      the date BUILD was last stamped

BUILD is a stored counter rather than something derived from git because
the app instances are deployed by rsync (deploy/deploy.sh) and have no
.git directory -- anything computed live from history would be blank in
production. Re-stamp with --bump-build before cutting a release or
regenerating the architecture documents.
"""
import os
import sys
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(HERE, "VERSION")

#: BUILD is always rendered at this width, so 1 reads as 00001 and the
#: stamp keeps a constant shape in page footers and filenames.
BUILD_DIGITS = 5

FIELDS = ("VERSION", "BUILD", "DATE")


def read(path=VERSION_FILE):
    """Return {'VERSION': '1.5', 'BUILD': '00001', 'DATE': 'YYYY-MM-DD'}."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    missing = [f for f in FIELDS if f not in out]
    if missing:
        raise ValueError("%s is missing %s" % (path, ", ".join(missing)))
    return out


def stamp(path=VERSION_FILE):
    """"Version 1.5 · build 00001" -- the form the documents carry."""
    v = read(path)
    return u"Version %s · build %s" % (v["VERSION"], v["BUILD"])


def pretty_date(path=VERSION_FILE):
    """"D Month YYYY" -- the long form the document covers use."""
    y, m, d = (int(part) for part in read(path)["DATE"].split("-"))
    return u"%d %s %d" % (d, date(y, m, d).strftime("%B"), y)


def next_build(current):
    """'00001' -> '00002'. Widens past five digits rather than wrapping."""
    return str(int(current) + 1).zfill(BUILD_DIGITS)


def write(values, path=VERSION_FILE):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for f in FIELDS:
            fh.write("%s=%s\n" % (f, values[f]))


def main(argv):
    values = read()
    if "--bump-build" in argv:
        values["BUILD"] = next_build(values["BUILD"])
        values["DATE"] = date.today().isoformat()
        write(values)
    if "--set" in argv:
        values["VERSION"] = argv[argv.index("--set") + 1].lstrip("vV")
        write(values)
    print("%s  (%s)" % (stamp(), read()["DATE"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

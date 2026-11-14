"""Which code the signer runs, so a site can tell it from its own.

verify imports `signer/` and `ovcrypto/` from its own tree, while the signer
runs the copy install.sh put in /opt/cl03-signer, and a deploy of verify never
touches that copy. `digest` is one hash over both folders' files; the two
sides compute it the same way, and Setup says so when they differ. `commit` is
what install.sh recorded, when it knew it.

Python 3.9 on purpose: a deploy may run it with the host's python3, which
is 3.9 on Amazon Linux 2023.

    python3 -m signer.version /opt/cl03-signer     # prints the digest
"""

from __future__ import annotations

import hashlib
import os
import sys

FOLDERS = ("signer", "ovcrypto")
#: Folders one side has and the other may not: deploy.sh keeps every
#: `deploy/` off the instance, and install.sh copies the signer's.
SKIP = {"__pycache__", "deploy"}


def digest(root: str) -> str:
    """SHA-256 over the Python files under `root`/signer and
    `root`/ovcrypto, by relative path and content: the code both copies have,
    however each was made. "" if there is none."""
    h = hashlib.sha256()
    found = False
    for folder in FOLDERS:
        base = os.path.join(root, folder)
        for here, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if d not in SKIP)
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(here, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                with open(path, "rb") as handle:
                    # Line endings as git stores them: a Windows checkout
                    # and an archive of it are the same code.
                    content = handle.read().replace(b"\r\n", b"\n")
                h.update(rel.encode() + b"\0")
                h.update(hashlib.sha256(content).digest())
                found = True
    return h.hexdigest() if found else ""


_digests = {}


def cached_digest(root: str) -> str:
    """`digest`, once per process: the files change only with an install,
    which restarts the signer, or a deploy, which restarts gunicorn."""
    if root not in _digests:
        _digests[root] = digest(root)
    return _digests[root]


def commit(root: str) -> str:
    """The commit install.sh recorded in `root`/COMMIT, or ""."""
    try:
        with open(os.path.join(root, "COMMIT"), encoding="ascii") as handle:
            value = handle.read().strip()
    except (OSError, ValueError):
        return ""
    return value if len(value) == 40 and all(
        c in "0123456789abcdef" for c in value) else ""


def here() -> str:
    """The folder this package was loaded from: the signer's own root."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


if __name__ == "__main__":
    print(digest(sys.argv[1] if len(sys.argv) > 1 else here()))

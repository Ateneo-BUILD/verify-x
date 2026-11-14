"""The cache-buster in every static URL: `?v={{ APP_VERSION }}`.

Not the time each process started: gunicorn imports settings in every
worker, and restarts each worker after about a thousand requests, so the
workers on one server would stamp different URLs, and every server behind
the load balancer would differ again. A browser whose next page came from
another worker would download the scripts again -- about 154 KB on the
Verify page -- although not a byte had changed.

So it is a digest of the static files themselves: the same for every
process serving the same files, and different exactly when a file is. It is
automatic; nothing is ever typed by hand. With `DEBUG` on, the context
processor stamps the current time on every request instead.
"""
import hashlib
import time
from pathlib import Path


def static_version(dirs):
    """A short digest of every file under `dirs`, in STATICFILES_DIRS form:
    a path, or a (prefix, path) pair. The current time if none exists."""
    digest = hashlib.sha256()
    found = False
    for entry in dirs:
        root = Path(entry[1] if isinstance(entry, (tuple, list)) else entry)
        if not root.is_dir():
            continue
        found = True
        files = sorted(p for p in root.rglob("*")
                       if p.is_file() and not p.name.startswith("."))
        for path in files:
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    if not found:
        return str(int(time.time()))
    return digest.hexdigest()[:12]

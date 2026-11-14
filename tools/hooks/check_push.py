"""pre-push guard: refuse to push a commit that carries a live secret.

A credential that reaches a pushed commit is published for good: deleting
it in a later commit leaves it in the earlier one. So the check runs before
anything leaves, on every commit being sent.

git hands a pre-push hook one line per ref on stdin:

    <local ref> <local sha> <remote ref> <remote sha>

Every commit about to leave is checked, contents AND message, for:

  - the value of every credential in this checkout's .env, and in the
    site configuration file VERIFY_SITE names (deploy/deploy.sh's), matched
    literally: the live credentials this deployment actually runs on, so
    nothing has to guess what a secret looks like. A credential is a key
    whose NAME says so (SECRET_NAME below). Not every .env value: that
    would refuse every commit over DJANGO_ALLOWED_HOSTS, whose value is
    also the default in settings.py -- and a guard that refuses everything
    is a guard somebody switches off.
  - a PEM private key block

Only paths are ever printed, never a value -- a guard that echoed what it
caught would put the secret in a terminal scrollback instead.

Standard library only: it runs before anything is installed.
"""
import os
import re
import subprocess
import sys
import tempfile

ZERO = "0" * 40
MIN_LEN = 12
PEM = r"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----"
SECRET_NAME = re.compile(
    r"SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE|WRAP_KEY|CLIENT_ID", re.I)
NOT_SECRET = re.compile(r"_(PATH|URL|FILE|DIR)$", re.I)


def git(repo, *args, check=True):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True,
                          text=True, check=check).stdout


def env_values(repo, environ=os.environ):
    """{(file, KEY): value} for every credential long enough to matter, in
    this checkout's .env and in the site configuration VERIFY_SITE names.
    The site configuration lives outside the checkout, which is exactly why
    nothing else here would know its values."""
    paths = [os.path.join(repo, ".env")]
    if environ.get("VERIFY_SITE"):
        paths.append(os.path.join(repo, environ["VERIFY_SITE"]))
    values = {}
    for path in paths:
        if not os.path.isfile(path):
            continue
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip("'\"")
            if (len(value) >= MIN_LEN and SECRET_NAME.search(key)
                    and not NOT_SECRET.search(key)):
                values[(path, key)] = value
    return values


def outgoing(repo, remote, stdin_lines):
    """The commits a push would send, across every ref being pushed."""
    commits = []
    for line in stdin_lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        _, local_sha, _, remote_sha = parts
        if local_sha == ZERO:
            continue                        # deleting a remote ref
        # A remote tip this clone has never fetched cannot bound a range, so
        # fall back to "everything the remote is not known to hold".
        if remote_sha != ZERO and subprocess.run(
                ["git", "-C", repo, "cat-file", "-e", remote_sha + "^{commit}"],
                capture_output=True).returncode == 0:
            spec = [remote_sha + ".." + local_sha]
        else:
            spec = [local_sha, "--not", "--remotes=" + remote]
        commits += git(repo, "rev-list", *spec).split()
    return list(dict.fromkeys(commits))


def find_leaks(repo, commits, values):
    """[(commit, where, what)] for every secret the commits would carry."""
    leaks = []
    if not commits:
        return leaks
    fd, patterns = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("".join(v + "\n" for v in values.values()))
        for i in range(0, len(commits), 50):
            batch = commits[i:i + 50]
            if values:
                for hit in git(repo, "grep", "-l", "-F", "-f", patterns,
                               *batch, check=False).splitlines():
                    commit, _, path = hit.partition(":")
                    leaks.append((commit, path, "a live credential"))
            for hit in git(repo, "grep", "-l", "-E", "-e", PEM, *batch,
                           check=False).splitlines():
                commit, _, path = hit.partition(":")
                leaks.append((commit, path, "a private key block"))
    finally:
        os.remove(patterns)
    for commit in commits:
        message = git(repo, "log", "-1", "--format=%B", commit)
        if any(v in message for v in values.values()):
            leaks.append((commit, "(commit message)", "a live credential"))
        if re.search(PEM, message):
            leaks.append((commit, "(commit message)", "a private key block"))
    return leaks


def main(argv, stdin):
    repo = git(os.getcwd(), "rev-parse", "--show-toplevel").strip()
    remote = argv[1] if len(argv) > 1 else "origin"
    values = env_values(repo)
    leaks = find_leaks(repo, outgoing(repo, remote, stdin.read().splitlines()),
                       values)
    if not values:
        print("pre-push: no .env here and no VERIFY_SITE, so only private "
              "key blocks were checked.", file=sys.stderr)
    if not leaks:
        return 0
    print("pre-push: REFUSED. These commits would publish a secret:",
          file=sys.stderr)
    for commit, where, what in leaks:
        print("  %s  %s  (%s)" % (commit[:10], where, what), file=sys.stderr)
    print("Take it out of history (git filter-repo --replace-text), not just "
          "out of the next commit -- the old commit still carries it.",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv, sys.stdin))

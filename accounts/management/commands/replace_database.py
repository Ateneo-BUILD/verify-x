"""Put another copy of the database in the live one's place, safely.

    sudo systemctl stop gunicorn
    python manage.py replace_database /path/to/copy.sqlite3 --confirm verify.example.org
    python manage.py migrate
    sudo systemctl start gunicorn

The only way a database should be swapped: a deploy's `--sync-db` runs it,
and so does a restore from a backup (docs/deploy-aws.md, "Restoring
the database"). It refuses a copy whose keys this site cannot
open or whose keys differ from this site's, carries in this site's keys the
copy lacks, says what else the copy does not have -- phones, document
records, revocations -- and backs the live database up before anything
changes (accounts/database_swap.py).

`--confirm` names the site: its host name, one of DJANGO_ALLOWED_HOSTS
other than an address or localhost, typed, so a command pointed at the wrong
server does nothing. `--check` reports and
changes nothing.
"""

import time
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connections

from accounts import database_swap


class Command(BaseCommand):
    help = "Replace the live database with a checked copy, backing it up first."

    def add_arguments(self, parser):
        parser.add_argument("copy", help="The database file to put in place.")
        parser.add_argument(
            "--confirm", default="",
            help="This site's host name, as in DJANGO_ALLOWED_HOSTS.")
        parser.add_argument(
            "--check", action="store_true",
            help="Say what would happen and change nothing.")
        parser.add_argument(
            "--take-incoming-keys", action="store_true",
            help="Where the copy holds other keys than this site's under the "
                 "same epoch, take the copy's. What this site sealed with its "
                 "own no longer opens.")
        parser.add_argument(
            "--backup-dir", default="",
            help="Where the live database is copied first (default: backups/ "
                 "beside the code directory).")

    def handle(self, *args, **options):
        live = database_swap.live_path()
        copy = Path(options["copy"])
        if not copy.is_file():
            raise CommandError("no such file: %s" % copy)
        if not options["check"]:
            names = database_swap.site_names(settings.ALLOWED_HOSTS)
            if options["confirm"].lower() not in names:
                raise CommandError(
                    "name this site with --confirm: its host name, one of "
                    "DJANGO_ALLOWED_HOSTS that is not an address or localhost "
                    "(%s). Nothing was changed." % (", ".join(names) or "none"))
        # Django's own connection would hold the file open across the swap.
        connections.close_all()
        now = int(time.time())
        try:
            if options["check"]:
                result = database_swap.plan(
                    live, copy, now=now,
                    take_incoming_keys=options["take_incoming_keys"])
            else:
                result = database_swap.replace(
                    live, copy,
                    options["backup_dir"] or Path(settings.BASE_DIR).parent / "backups",
                    now=now, take_incoming_keys=options["take_incoming_keys"])
        except database_swap.SwapRefused as exc:
            for reason in exc.reasons:
                self.stderr.write("Refused: %s." % reason)
            raise CommandError("Nothing was changed.")
        for line in database_swap.describe(result):
            self.stdout.write(line)
        if options["check"]:
            self.stdout.write("It can be put in place; nothing was changed.")
            return
        if result["backup"]:
            self.stdout.write("The database it replaced is in %s (sha256 %s)."
                              % (result["backup"], result["backup_sha256"]))
        self.stdout.write("Replaced. Next: python manage.py migrate, then start "
                          "gunicorn.")

"""Empty the development store of eVerify responses.

`DebugCapture` keeps whole responses -- every field, and the face -- so the
printed document's sizing and quality can be measured against real data. That
makes it a table of complete identity records of real people, and it is meant
to be emptied as soon as a study is finished.

    python manage.py debug_cleanup            # delete everything
    python manage.py debug_cleanup --photos-only
    python manage.py debug_cleanup --dry-run

`--photos-only` is the softer option, exactly as `purge_login_attempts` has:
it drops the faces and keeps the field data, which is enough for the
credential-length half of the sizing work.

Nothing runs this on a timer, and that is deliberate -- a debug store that
quietly ages real people out over ninety days is a store somebody has stopped
thinking about. The same button is on `/debug-cleanup/`, where the gate is
open.
"""

from django.core.management.base import BaseCommand

from accounts import debug_store
from accounts.models import DebugCapture


class Command(BaseCommand):
    help = "Delete (or strip the faces from) the development eVerify store."

    def add_arguments(self, parser):
        parser.add_argument(
            "--photos-only", action="store_true",
            help="Clear the captured faces but keep the field data.")
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Report what would go, change nothing.")

    def handle(self, *args, **options):
        photos_only = options["photos_only"]
        rows = DebugCapture.objects.all()
        if photos_only:
            rows = rows.exclude(photo_data="")
        count = rows.count()

        what = "face(s) to clear" if photos_only else "capture(s) to delete"
        if options["dry_run"]:
            self.stdout.write("%d %s." % (count, what))
            return

        purged = debug_store.purge(photos_only=photos_only)
        done = "Cleared %d face(s)." if photos_only else "Deleted %d capture(s)."
        self.stdout.write(self.style.SUCCESS(done % purged))

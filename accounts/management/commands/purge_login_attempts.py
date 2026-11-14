"""Age out the refused sign-in log, which holds faces.

`LoginAttempt` records every National ID typed at the login page that named
no registered operator, with the face the liveness check handed back.
Most of those are strangers. Some of them are an operator who mistyped their
own card number, so the table accumulates photographs of colleagues taken
during a failed login, which is not something to keep forever.

Nothing calls this automatically -- how long the log is worth keeping is a
policy question for whoever runs the deployment, not a default this app
should pick. Run it from cron on the instance once that is decided:

    python manage.py purge_login_attempts --days 90

`--photos-only` is the softer option: it clears the captures and keeps the
rest of the row, so "who tried, with what ID, from where" is kept without
the faces.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import LoginAttempt


class Command(BaseCommand):
    help = "Delete (or strip the photos from) old refused sign-in attempts."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days", type=int, default=90,
            help="Age in days beyond which an attempt is purged (default 90).")
        parser.add_argument(
            "--photos-only", action="store_true",
            help="Clear the captured faces but keep the rows.")
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Report what would go, change nothing.")

    def handle(self, *args, **options):
        days = options["days"]
        if days < 0:
            self.stderr.write("--days cannot be negative.")
            return

        cutoff = timezone.now() - timezone.timedelta(days=days)
        stale = LoginAttempt.objects.filter(created_at__lt=cutoff)
        if options["photos_only"]:
            stale = stale.exclude(photo_data="")
        count = stale.count()

        what = "capture(s) to clear" if options["photos_only"] else "attempt(s) to delete"
        if options["dry_run"]:
            self.stdout.write(f"{count} {what}, older than {cutoff:%Y-%m-%d %H:%M}.")
            return

        if options["photos_only"]:
            stale.update(photo_data="")
            self.stdout.write(self.style.SUCCESS(f"Cleared {count} capture(s)."))
        else:
            stale.delete()
            self.stdout.write(self.style.SUCCESS(f"Deleted {count} attempt(s)."))

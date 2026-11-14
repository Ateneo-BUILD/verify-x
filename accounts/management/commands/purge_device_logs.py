"""Age out the phones' activity log.

`DeviceLogEntry` is an audit trail -- what each paired phone did, every
document it read and the verdict -- and an audit trail with no end date is a
record of people kept by omission. The default is 360 days;
`DEVICE_LOG_RETENTION_DAYS` sets the deployment's own, and `--days` one run's.

Measured from `received_at`, this server's own clock, never from the time the
phone claimed: the phone's clock is the phone's to set, and a record must not
be able to keep itself forever, or expire itself early, by what it says.

It runs daily: every deploy installs `purge-device-logs.timer`
(deploy/install-purge-timer.sh), as gunicorn's own user. By hand:

    python manage.py purge_device_logs [--days N] [--dry-run]

A refusal is an error, so a timer that runs it shows as failed.

**It deletes in batches**, each with its own transaction, so a long purge --
the first after the period is shortened -- never holds the database's one
write lock for long: a request waits for one batch at most. Each batch first
moves the phone's `DeviceLogMark` up to the highest-numbered record it
deletes, in the same transaction, so the chain's head outlasts the purge
(`device_log.ingest`).
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from accounts.models import DeviceLogEntry, DeviceLogMark

#: Records deleted per transaction.
BATCH = 2000
#: The longest retention a period may name: a hundred years. More is "keep
#: it forever", which is not a period, and far more is a date before year 1.
MAX_DAYS = 36500


class Command(BaseCommand):
    help = "Delete device activity log entries older than a retention period."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days", type=int, default=None,
            help="Age in days, by when the entry arrived here, beyond which "
                 "it is deleted (default DEVICE_LOG_RETENTION_DAYS, 360 "
                 "unless set).")
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Report what would go, change nothing.")

    def handle(self, *args, **options):
        days = options["days"]
        if days is None:
            days = settings.DEVICE_LOG_RETENTION_DAYS
        # Under a day would delete what phones sent today, and the timer runs
        # this unattended.
        if not 1 <= days <= MAX_DAYS:
            raise CommandError("A retention of %d days is refused: at least 1, "
                               "at most %d." % (days, MAX_DAYS))

        cutoff = timezone.now() - timezone.timedelta(days=days)
        stale = DeviceLogEntry.objects.filter(received_at__lt=cutoff)
        count = stale.count()

        if options["dry_run"]:
            self.stdout.write(
                f"{count} log entr{'y' if count == 1 else 'ies'} to delete, "
                f"received before {cutoff:%Y-%m-%d %H:%M}.")
            return

        deleted = 0
        while True:
            with transaction.atomic():
                rows = list(stale.order_by("pk").values_list(
                    "pk", "device_uuid", "seq", "record_hash")[:BATCH])
                if not rows:
                    break
                newest = {}
                for _pk, uuid, seq, digest in rows:
                    if uuid not in newest or seq > newest[uuid][0]:
                        newest[uuid] = (seq, bytes(digest))
                for uuid, (seq, digest) in newest.items():
                    mark, made = DeviceLogMark.objects.get_or_create(
                        device_uuid=uuid,
                        defaults={"head_seq": seq, "head_hash": digest})
                    if not made and seq > mark.head_seq:
                        mark.head_seq, mark.head_hash = seq, digest
                        mark.save(update_fields=["head_seq", "head_hash"])
                DeviceLogEntry.objects.filter(
                    pk__in=[row[0] for row in rows]).delete()
                deleted += len(rows)
        self.stdout.write(self.style.SUCCESS(
            f"Deleted {deleted} log entr{'y' if deleted == 1 else 'ies'}."))

"""New keys for an epoch whose own are gone, when no backup has them.

    python manage.py remake_epoch_keys --confirm verify.example.org

A site will not make new keys for an epoch documents were made in
(`credential_keys.epoch_key_row`): the new ones would fork the epoch, and
nothing would say so. Until the old ones are back -- from a backup, through
`manage.py replace_database` -- nothing is minted and no phone can sync, and
Setup says why. When no backup has them, this accepts the loss: it makes new
keys for the current epoch, and the documents made with the old ones never
open again. Everything after works as before.

`--confirm` names the site, as for replace_database.
"""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from accounts import credential_keys, database_swap


class Command(BaseCommand):
    help = "Make new keys for the current epoch when its own are lost."

    def add_arguments(self, parser):
        parser.add_argument(
            "--confirm", default="",
            help="This site's host name, as in DJANGO_ALLOWED_HOSTS.")

    def handle(self, *args, **options):
        names = database_swap.site_names(settings.ALLOWED_HOSTS)
        if options["confirm"].lower() not in names:
            raise CommandError(
                "name this site with --confirm: its host name (%s). Nothing "
                "was changed." % (", ".join(names) or "none"))
        lost = credential_keys.lost_epoch_keys()
        if not lost:
            raise CommandError("No key of the current epoch is lost; nothing was "
                               "changed.")
        epoch = credential_keys.current_epoch()
        for tier in (credential_keys.TIER_PUBLIC, credential_keys.TIER_RESTRICTED):
            credential_keys.epoch_key_row(epoch, tier, accept_loss=True)
        credential_keys.logger.error(
            "remake_epoch_keys: new keys for epoch %d (%s): documents made "
            "with the old ones no longer open", epoch, ", ".join(lost))
        self.stdout.write("Made new keys for %s. Documents made with the old "
                          "ones no longer open; minting and syncing work "
                          "again." % ", ".join(lost))

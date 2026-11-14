"""System checks that read the database.

Tagged `database`, so `manage.py migrate` -- every deploy -- runs them, as
does `manage.py check --database default`. migrate runs them BEFORE it
applies anything, against a schema that may lag the code: so they read only
long-standing columns, and a database error makes them step aside rather
than stop the deploy that would fix it.
"""

from django.core import checks
from django.db import DatabaseError

#: The shortest lease a bundle is made with, as the signer's
#: `config.MIN_LEASE_SECONDS`.
MIN_LEASE_SECONDS = 3600


@checks.register()
def bundle_settings(app_configs=None, **kwargs):
    """What every bundle is made from, so a sync cannot fail on it.

    Not a database check: `manage.py check` and every deploy's run it, and
    a bundle made in key-file mode with either wrong would be refused by
    `ovcrypto.bundle` at every sync.
    """
    from django.conf import settings
    from ovcrypto import bundle as bundle_mod

    found = []
    if settings.DEVICE_LEASE_SECONDS < MIN_LEASE_SECONDS:
        found.append(checks.Error(
            "DEVICE_LEASE_SECONDS is %d: a phone's lease is at least %d "
            "seconds." % (settings.DEVICE_LEASE_SECONDS, MIN_LEASE_SECONDS),
            hint="A lease over on arrival leaves the next sync unguarded, "
                 "and neither the signer nor ovcrypto signs one.",
            id="accounts.E001"))
    if not 0 < settings.CREDENTIAL_ISSUER_KEY_ID < bundle_mod.CHAINS_DIGEST_ID:
        found.append(checks.Error(
            "CREDENTIAL_ISSUER_KEY_ID is %d: a key id is from 1 to %d."
            % (settings.CREDENTIAL_ISSUER_KEY_ID,
               bundle_mod.CHAINS_DIGEST_ID - 1),
            hint="The highest u32 is the trust entry that binds a bundle's "
                 "certificates, never a key's.",
            id="accounts.E002"))
    return found


#: The longest SIGNER_QUEUE_TIMEOUT_SECONDS. A request holds one of
#: gunicorn's threads while it waits (two a worker), and a signer that does
#: not answer within this is not going to.
MAX_SIGNER_QUEUE_TIMEOUT = 25


@checks.register()
def signer_queue_settings(app_configs=None, **kwargs):
    """A signer that dials out (`accounts.signer_queue`): its key is one, and
    a request waits for it a sensible time. Judged at every deploy, since a
    wrong key otherwise shows only as every document's plain QR."""
    from django.conf import settings
    from signer import poll

    found = []
    if settings.SIGNER_QUEUE_KEY:
        try:
            poll.parse_key(settings.SIGNER_QUEUE_KEY)
        except ValueError:
            found.append(checks.Error(
                "SIGNER_QUEUE_KEY is not 32 bytes as 64 hex characters or "
                "base64.",
                hint="It is the signer's credential poll-key, the same value "
                     "at both ends. Until it is one, the signer's polls are "
                     "refused and nothing is signed.",
                id="accounts.E004"))
        if settings.SIGNER_SOCKET:
            found.append(checks.Warning(
                "SIGNER_SOCKET and SIGNER_QUEUE_KEY are both set: the socket "
                "is used, and no job is ever queued.",
                hint="Leave one empty: SIGNER_SOCKET beside a signer on this "
                     "host, SIGNER_QUEUE_KEY for one that dials out.",
                id="accounts.W005"))
    if settings.SIGNER_QUEUE_MAX_WAITING < 1 or (
            settings.GUNICORN_THREADS
            and settings.SIGNER_QUEUE_MAX_WAITING >= settings.GUNICORN_THREADS):
        found.append(checks.Warning(
            "SIGNER_QUEUE_MAX_WAITING is %d and GUNICORN_THREADS %d: the "
            "first must be at least 1 and below the second."
            % (settings.SIGNER_QUEUE_MAX_WAITING, settings.GUNICORN_THREADS),
            hint="This compares the two settings as this process reads them "
                 "from .env, not gunicorn's running configuration, which the "
                 "app cannot see; the site kit's gunicorn.conf.py takes its "
                 "threads from GUNICORN_THREADS. A worker whose every thread "
                 "waits for the signer cannot take the signer's answer.",
            id="accounts.W006"))
    if not 1 <= settings.SIGNER_QUEUE_TIMEOUT_SECONDS <= MAX_SIGNER_QUEUE_TIMEOUT:
        found.append(checks.Error(
            "SIGNER_QUEUE_TIMEOUT_SECONDS is %d: it is from 1 to %d."
            % (settings.SIGNER_QUEUE_TIMEOUT_SECONDS, MAX_SIGNER_QUEUE_TIMEOUT),
            hint="A request waits this long for the signer's answer, holding "
                 "one of gunicorn's threads; 10 is the default.",
            id="accounts.E005"))
    return found


#: Shorter than this, the activity log is gone before most questions about
#: it are asked; allowed, and said.
SHORT_RETENTION_DAYS = 30


@checks.register()
def device_log_retention(app_configs=None, **kwargs):
    """The period the daily purge deletes by, judged at every deploy's
    migrate, before the timer runs it unattended."""
    from django.conf import settings

    from accounts.management.commands.purge_device_logs import MAX_DAYS

    days = settings.DEVICE_LOG_RETENTION_DAYS
    if not 1 <= days <= MAX_DAYS:
        return [checks.Error(
            "DEVICE_LOG_RETENTION_DAYS is %d: a period is from 1 to %d days."
            % (days, MAX_DAYS),
            hint="The daily purge refuses it, and the activity log is not "
                 "aged out at all until it is fixed.",
            id="accounts.E003")]
    if days < SHORT_RETENTION_DAYS:
        return [checks.Warning(
            "DEVICE_LOG_RETENTION_DAYS is %d: the daily purge deletes every "
            "activity record older than that, for good." % days,
            hint="Check it is not a typing slip; 360 is the default.",
            id="accounts.W003")]
    return []


@checks.register(checks.Tags.database)
def rows_the_old_bridge_may_have_promoted(app_configs=None, databases=None, **kwargs):
    """A site admin whose digital ID is a Django staff username.

    An earlier Django-admin bridge bound a staff account to whichever verify
    row had the username as its digital ID, and promoted that row to site
    admin. Organization admins type digital IDs, so such a row may have
    been planted. The bridge no longer looks there, but what it promoted
    stays promoted -- and a planted row's accomplice could still sign in as
    it. Nothing here can tell a legitimate site admin from a planted one, so
    it is reported, never changed.
    """
    if not databases:
        return []
    from django.contrib.auth import get_user_model

    from accounts.models import BRIDGE_PREFIX, User

    try:
        staff = set(get_user_model().objects.filter(is_active=True)
                    .exclude(is_staff=False, is_superuser=False)
                    .values_list("username", flat=True))
        rows = list(User.objects.filter(is_site_admin=True, digital_national_id__in=staff)
                    .exclude(national_id_card_number__startswith=BRIDGE_PREFIX)
                    .values_list("pk", "national_id_card_number", "digital_national_id"))
    except DatabaseError:
        return []
    return [checks.Warning(
        f"verify user {pk} (card ending {card[-4:]}) is a site admin, and its "
        f"digital ID is the Django staff username '{username}'.",
        hint=("An earlier Django-admin bridge could bind that staff account to "
              "this row and promote it. Confirm the row is that person's, "
              "or clear is_site_admin (0046 does, on every row that is not a "
              "Django account's own; accounts.W002 reports any written since)."),
        id="accounts.W001") for pk, card, username in rows]


@checks.register(checks.Tags.database)
def roles_outside_the_bridge(app_configs=None, databases=None, **kwargs):
    """A row that is a site admin, or an admin of every organization, but is
    neither a Django account's bridge row nor designated by a superuser.

    A bridge row's role follows its Django account
    (accounts.models.bridge_roles), and any other row holds one only by a
    superuser's designation, which records who and when
    (accounts/admin_roles.py). 0046 cleared every row that was neither,
    so a role with no designation recorded was written straight into the
    database. It is reported, never changed. Each flag is read in its own
    query: is_all_org_admin arrives with 0046 and the designation with 0047,
    and migrate runs this before applying them.
    """
    if not databases:
        return []
    from accounts.models import BRIDGE_PREFIX, User

    found = []
    for flag, role in (("is_site_admin", "a site admin"),
                       ("is_all_org_admin", "an admin of every organization")):
        try:
            rows = list(User.objects.filter(**{flag: True}, admin_role_granted_at=None)
                        .exclude(national_id_card_number__startswith=BRIDGE_PREFIX)
                        .values_list("pk", "national_id_card_number"))
        except DatabaseError:
            continue
        found += [checks.Warning(
            f"verify user {pk} (card ending {card[-4:]}) is {role}, but is not a "
            f"Django account's own row and no superuser's designation is recorded.",
            hint=("A Django account's own row follows the account, and any other row "
                  "holds a role only by a superuser's designation in Django admin, "
                  "which records who and when. This one was "
                  "written some other way: designate it in Django admin if it is "
                  f"meant, or clear it (User.objects.filter(pk={pk}).update({flag}="
                  "False)), and find out how it was written."),
            id="accounts.W002") for pk, card in rows]
    return found


@checks.register(checks.Tags.database)
def stored_keys_that_do_not_open(app_configs=None, databases=None, **kwargs):
    """Stored keys this site's CREDENTIAL_EPOCH_WRAP_KEY does not open: the
    epoch keys phones are still given, and every activity-log key.

    Setup says so in red, and so does this: without it a deploy with the
    wrong value, after `rewrap_keys` or a restore, would finish as if all
    were well -- /health/ answers 200 -- while every sync answered 503.
    Every deploy's migrate runs it, and `deploy.sh check`. No wrap key at
    all is `credential_keys.missing()`'s to report, not this.
    """
    if not databases:
        return []
    from accounts import credential_keys
    from accounts.credentials import CredentialError
    from accounts.models import DeviceLogKey

    try:
        wrapper = credential_keys._wrapper()
    except CredentialError:
        return []
    try:
        found = credential_keys.unreadable_epoch_keys()
        found += ["log key %d" % row.pk for row in DeviceLogKey.objects.order_by("pk")
                  if not credential_keys.unwraps_to(row.public_key,
                                                    row.wrapped_private_key, wrapper)]
    except DatabaseError:
        return []
    if not found:
        return []
    return [checks.Warning(
        "%d stored key(s) do not open with CREDENTIAL_EPOCH_WRAP_KEY: %s."
        % (len(found), ", ".join(found)),
        hint=("Phones cannot sync while an epoch key does not open, and an upload "
              "sealed to a log key that does not cannot be read. Is "
              "CREDENTIAL_EPOCH_WRAP_KEY the key they were made or re-wrapped "
              "under (manage.py rewrap_keys)? A database from before the rename "
              "to CL03 needs rewrap_keys --before-cl03. A database brought from "
              "another site keeps that site's key."),
        id="accounts.W004")]

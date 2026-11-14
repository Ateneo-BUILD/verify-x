"""Site admins are Django superusers, and nobody else.

A Django superuser's bridge row is a site administrator; a Django staff
account that is not a superuser administers every organization and nothing
site-wide (the new User.is_all_org_admin); no other row is either.
Transactions such an admin logs in an organization they are not a member of
are stamped acting_as_all_org_admin.

The data step re-derives both flags for every row that has either or is a
bridge row (accounts.models.bridge_roles), so:

  * a row someone ticked "site admin" on -- an eVerify sign-in, not a Django
    account -- stops being one. Each is named in the output, by id and the
    last four digits of its card. Its memberships are untouched; if it has
    none it can no longer enter any organization, which is the decision --
    and its phones lose the restricted tier too, as a demoted bridge row's
    do (accounts/django_bridge.py), or they would go on reading every
    organization's holders for a person who may enter none.
  * a staff (not superuser) account's bridge row stops being a site admin
    and becomes an admin of every organization.

Going back removes the two columns; the cleared site-admin flags are not put
back (restore the database backup taken before the deploy to undo that).
"""

import re

from django.conf import settings
from django.db import migrations, models

BRIDGE_PREFIX = "ADMIN"


def roles(django_user):
    # accounts.models.bridge_roles, on the historical models.
    if django_user is None or not django_user.is_active:
        return False, False
    if django_user.is_superuser:
        return True, False
    return False, bool(django_user.is_staff)


def rederive(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    Membership = apps.get_model("accounts", "Membership")
    DjangoUser = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    rows = User.objects.filter(
        models.Q(is_site_admin=True)
        | models.Q(national_id_card_number__startswith=BRIDGE_PREFIX))
    for row in rows:
        card = row.national_id_card_number
        django_user = None
        if card.startswith(BRIDGE_PREFIX) and re.fullmatch(
                r"[0-9]{11}", card[len(BRIDGE_PREFIX):]):
            django_user = DjangoUser.objects.filter(
                pk=int(card[len(BRIDGE_PREFIX):])).first()
        site, every_org = roles(django_user)
        withdraw = (not site and not every_org and row.device_restricted_tier
                    and not Membership.objects.filter(user_id=row.pk).exists())
        if (row.is_site_admin, row.is_all_org_admin) == (site, every_org) \
                and not withdraw:
            continue
        if row.is_site_admin and not site:
            print(f"\n  0046: user {row.pk} (card ending {card[-4:]}) is no longer "
                  f"a site admin" + (", now an admin of every organization"
                                     if every_org else "")
                  + ("; it has no membership, so its phones' restricted tier is "
                     "withdrawn" if withdraw else ""), end="")
        update = {"is_site_admin": site, "is_all_org_admin": every_org}
        if withdraw:
            update.update(device_restricted_tier=False,
                          restricted_tier_granted_by=None,
                          restricted_tier_granted_at=None)
        User.objects.filter(pk=row.pk).update(**update)


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0045_rate_limit_hits'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_all_org_admin',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='transaction',
            name='acting_as_all_org_admin',
            field=models.BooleanField(default=False),
        ),
        migrations.RunPython(rederive, migrations.RunPython.noop),
    ]

"""Move the existing single tenant into one organization.

The rule this encodes: **an existing deployment must see no change at all**
until somebody creates a second organization. So every user keeps the role
they already hold, every location and transaction type follows them into one
organization seeded with the credentials the site is already using, and every
past transaction is attributed to it.

Existing admins become site admins as well as organization admins. That is
not a privilege expansion: in the single-tenant app an admin already sets the
site's login method and its SSO credentials, so site administration is
exactly what `role="admin"` has always meant here.

A genuinely fresh database has nothing to preserve and gets no organization
-- the first one is created from the Site Administration page.
"""

import os

from django.conf import settings
from django.db import migrations


#: The one organization an existing single-tenant deployment's locations,
#: transaction types, operators and eVerify client move into. Override per
#: instance with VERIFY_DEFAULT_ORG_NAME in .env before the first migrate.
DEFAULT_ORG_NAME = "PSA"


def _dotenv():
    """The instance .env, parsed directly.

    deploy.sh exports .env before calling migrate, so os.environ is normally
    enough. Reading the file too means the seeding does not silently produce
    an organization with no credentials when migrate is run any other way --
    by hand, or from a shell that did not source it.
    """
    values = {}
    path = os.path.join(settings.BASE_DIR, ".env")
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def _setting(dotenv, key, default=""):
    """Environment first, then the .env file, then the default."""
    return os.environ.get(key) or dotenv.get(key) or default


def _env_everify(dotenv):
    return {
        "everify_base_url": _setting(dotenv, "EVERIFY_BASE_URL",
                                     "https://ws.everify.gov.ph/api"),
        "everify_client_id": _setting(dotenv, "EVERIFY_CLIENT_ID"),
        "everify_client_secret": _setting(dotenv, "EVERIFY_CLIENT_SECRET"),
        "everify_public_api_key": _setting(dotenv, "EVERIFY_PUBLIC_API_KEY"),
    }


def seed(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    Membership = apps.get_model("accounts", "Membership")
    SiteSettings = apps.get_model("accounts", "SiteSettings")
    User = apps.get_model("accounts", "User")
    Location = apps.get_model("accounts", "Location")
    TransactionType = apps.get_model("accounts", "TransactionType")
    Transaction = apps.get_model("accounts", "Transaction")

    dotenv = _dotenv()
    env = _env_everify(dotenv)
    org_name = _setting(dotenv, "VERIFY_DEFAULT_ORG_NAME", DEFAULT_ORG_NAME)

    # The credentials that sign operators in are site-level. Fill them from
    # the environment the site is already running with, so the login page
    # behaves identically the moment this lands.
    site = SiteSettings.objects.filter(pk=1).first()
    if site is None and env["everify_client_id"]:
        site = SiteSettings(pk=1)
    if site is not None:
        for field, value in env.items():
            if value and not getattr(site, field, ""):
                setattr(site, field, value)
        site.save()

    if Organization.objects.exists():
        return

    has_legacy_data = (User.objects.exists() or Location.objects.exists()
                       or TransactionType.objects.exists()
                       or Transaction.objects.exists())
    if not has_legacy_data:
        return

    org = Organization.objects.create(name=org_name, **env)

    for user in User.objects.all():
        Membership.objects.create(organization=org, user=user, role=user.role)
        if user.role == "admin" and not user.is_site_admin:
            user.is_site_admin = True
            user.save(update_fields=["is_site_admin"])

    Location.objects.filter(organization__isnull=True).update(organization=org)
    TransactionType.objects.filter(organization__isnull=True).update(organization=org)
    Transaction.objects.filter(organization__isnull=True).update(organization=org)


def unseed(apps, schema_editor):
    """Reverse the seeding without destroying anything.

    Location and TransactionType point at Organization with on_delete=CASCADE,
    so deleting the organizations first would take every location and
    transaction type with it. Detach them before the delete -- at this point
    0018 has been unapplied, so the column is nullable again.
    """
    Membership = apps.get_model("accounts", "Membership")
    for membership in Membership.objects.select_related("user"):
        user = membership.user
        if user.role != membership.role:
            user.role = membership.role
            user.save(update_fields=["role"])

    apps.get_model("accounts", "Location").objects.update(organization=None)
    apps.get_model("accounts", "TransactionType").objects.update(organization=None)
    apps.get_model("accounts", "Transaction").objects.update(organization=None)

    Membership.objects.all().delete()
    apps.get_model("accounts", "Organization").objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0016_organization_membership"),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]

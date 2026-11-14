"""The Django-admin bridge's row follows its Django account.

A Django staff or superuser account opens this site's pages as a site
administrator through the bridge (verify/views/helpers.py,
`_get_session_user`), which keeps a row of its own whose card number is
ADMIN and the Django id. Two things keep that row from outliving the
account:

  * every request made on a bridge row re-checks the Django login, and ends
    the session when it is gone, inactive or no longer staff (helpers.py);
  * here: when the Django account is deactivated, loses staff, or is
    deleted, its row stops being a site administrator at once, so it is not
    listed or counted as one either, and any restricted tier its phones had
    is withdrawn. Signing in through Django admin again as staff makes it a
    site administrator again; the tier needs a new grant.

These run on save() and delete(), which is what Django admin uses. A bulk
QuerySet.update() of Django accounts sends no signal: the session check
still ends their sessions, but run the change through save(), or demote by
hand, to clear the rows.

Who is a site administrator (accounts.models.bridge_roles): a superuser is
one; a staff account that is not a superuser administers every organization
and nothing site-wide. Saving a Django account re-derives its row's two
flags, so taking or giving superuser status takes effect here at once -- and
at the row's next request through the bridge even when no signal ran.
"""

import logging

from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.db.models.signals import post_delete, post_save

from verify.sessions import mark_signed_in

logger = logging.getLogger(__name__)


def _qualifies(django_user):
    return bool(django_user.is_active
                and (django_user.is_staff or django_user.is_superuser))


def _demote(django_user, why):
    """Neither role, and its phones read the public tier only: phones it
    paired while bridged keep syncing, and must not keep every
    organization's holders."""
    from . import restricted_tier
    from .models import User, bridge_card

    row = User.objects.filter(
        national_id_card_number=bridge_card(django_user.pk)).first()
    if row is None:
        return
    if row.is_site_admin or row.is_all_org_admin:
        User.objects.filter(pk=row.pk).update(is_site_admin=False,
                                              is_all_org_admin=False)
        logger.warning("Django-admin bridge row for django user %s is no "
                       "longer a site admin or an admin of every "
                       "organization: the account was %s", django_user.pk, why)
    if row.device_restricted_tier:
        restricted_tier.withdraw(row, None, f"django account {why}")


def _resync(django_user):
    """Still staff: the row's two flags follow superuser status."""
    from .models import User, bridge_card, bridge_roles

    site, every_org = bridge_roles(django_user)
    changed = User.objects.filter(
        national_id_card_number=bridge_card(django_user.pk)).exclude(
        is_site_admin=site, is_all_org_admin=every_org).update(
        is_site_admin=site, is_all_org_admin=every_org)
    if changed:
        logger.warning("Django-admin bridge row for django user %s: site "
                       "admin %s, admin of every organization %s",
                       django_user.pk, site, every_org)


def _saved(sender, instance, **kwargs):
    if not _qualifies(instance):
        _demote(instance, "deactivated or lost staff")
    else:
        _resync(instance)


def _deleted(sender, instance, **kwargs):
    _demote(instance, "deleted")


def _signed_in(sender, request, user, **kwargs):
    """A Django admin login starts the shared session's absolute lifetime,
    as a verify sign-in does (verify/sessions.py)."""
    session = getattr(request, "session", None)
    if session is not None:
        mark_signed_in(session)


def connect():
    post_save.connect(_saved, sender=settings.AUTH_USER_MODEL,
                      dispatch_uid="accounts.django_bridge.saved")
    post_delete.connect(_deleted, sender=settings.AUTH_USER_MODEL,
                        dispatch_uid="accounts.django_bridge.deleted")
    user_logged_in.connect(_signed_in,
                           dispatch_uid="accounts.django_bridge.signed_in")

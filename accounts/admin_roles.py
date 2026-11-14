"""Designating a person a site admin or admin of every organization.

A Django account's own bridge row takes its role from the account
(accounts.models.bridge_roles). A superuser may also designate any
person -- an eVerify sign-in -- as either

  * a site admin: every site power except one, publishing or starting an
    organization's signing key, which stays a superuser's own act
    (User.switches_signing_keys); or
  * an admin of every organization: enters every active organization as its
    admin, with no site power at all.

Only a superuser designates (in Django admin, accounts/admin.py), so
deployment-wide power always traces back to one: a designated site admin
cannot designate anybody. Every designation records who made it and when,
and every change is logged. A bridge row is never designated -- its role
follows its Django account.
"""

import logging

from django.utils import timezone

from .models import User

logger = logging.getLogger(__name__)

#: The roles a designation can give, as the two flags they set.
ROLES = {
    None: (False, False),
    "site_admin": (True, False),
    "all_org_admin": (False, True),
}


def role_of(person):
    """The role name `person` holds, or None."""
    if person.is_site_admin:
        return "site_admin"
    if person.is_all_org_admin:
        return "all_org_admin"
    return None


def designate(person, role, actor, via):
    """Give `person` `role` (a key of ROLES; None takes it away), recorded as
    `actor`'s decision. `actor` is the superuser's own row (None when the
    Django account has never opened this site's pages)."""
    if person.is_bridge_row:
        raise ValueError("a Django account's own row follows its account")
    site, every_org = ROLES[role]
    person.is_site_admin, person.is_all_org_admin = site, every_org
    person.admin_role_granted_by = actor if role else None
    person.admin_role_granted_at = timezone.now() if role else None
    person.save(update_fields=["is_site_admin", "is_all_org_admin",
                               "admin_role_granted_by", "admin_role_granted_at"])
    logger.warning("User %s designated %s by user %s (%s)", person.pk,
                   role or "neither site admin nor admin of every organization",
                   actor.pk if actor else None, via)


def designated():
    """Everyone holding a role by designation, for Django admin and Setup."""
    return (User.objects.exclude(admin_role_granted_at=None)
            .select_related("admin_role_granted_by")
            .order_by("last_name", "given_name", "pk"))

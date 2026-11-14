"""Who may let a person's phones read holders' details, and the record of it.

`User.device_restricted_tier` lets a person's phones decrypt the restricted
tier of a credential: the holder's name, birth date and ID numbers. Epoch keys
are site-wide, so that is every organization's documents, not one's. An admin
of one organization therefore cannot hand it out:

  * a person an organization admin adds starts without it;
  * a site administrator grants or withdraws it, on the Site organization
    page or on Setup, and a superuser may in Django admin;
  * every grant records who made it and when, and every change is logged.

Withdrawing reaches every phone the person owns at that phone's next
sync.
"""

import logging

from django.utils import timezone

from .models import User

logger = logging.getLogger(__name__)


def grant(person, actor, via):
    """Let `person`'s phones read the restricted tier. `actor` is the User who
    decided it (None when it was a Django account with no row here)."""
    person.device_restricted_tier = True
    person.restricted_tier_granted_by = actor
    person.restricted_tier_granted_at = timezone.now()
    person.save(update_fields=["device_restricted_tier",
                               "restricted_tier_granted_by",
                               "restricted_tier_granted_at"])
    logger.warning("Restricted tier granted to user %s by user %s (%s)",
                   person.pk, actor.pk if actor else None, via)


def withdraw(person, actor, via):
    """Confirm documents only, from each of `person`'s phones' next sync."""
    person.device_restricted_tier = False
    person.restricted_tier_granted_by = None
    person.restricted_tier_granted_at = None
    person.save(update_fields=["device_restricted_tier",
                               "restricted_tier_granted_by",
                               "restricted_tier_granted_at"])
    logger.warning("Restricted tier withdrawn from user %s by user %s (%s)",
                   person.pk, actor.pk if actor else None, via)


def holders():
    """Everyone whose phones read the restricted tier, for Setup's list."""
    return (User.objects.filter(device_restricted_tier=True)
            .select_related("restricted_tier_granted_by")
            .order_by("last_name", "given_name", "pk"))

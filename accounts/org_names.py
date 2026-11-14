"""Who may rename an organization, and the record of every rename.

An organization's name is what its documents say issued them: under the
deployment key, the credential's issuer claim is `Organization.name`, signed
into the public tier every phone reads (accounts/credentials.py).

So once an organization has verified anybody, renaming it is a site admin's
act: on the Site page, or in Django admin as a superuser. Before that its own
admins set it up as they like. Every rename is logged with who made it, on
every path. The name a certified key carries is bound by its certificate
instead, and the signer refuses one organization's name to another.
"""

import logging
import unicodedata

from .models import IssuedCredential, Organization, Transaction

logger = logging.getLogger(__name__)

#: What an organization admin is told when the name is no longer theirs.
LOCKED_MESSAGE = (
    "Only a site administrator can rename an organization that has verified "
    "anybody: the name is what its documents say issued them.")


def has_issued(org):
    """Has `org` verified anybody -- a successful verification logged, or a
    credential issued? A failed attempt puts the name on no document."""
    return (org.pk is not None
            and (Transaction.objects.filter(
                     organization=org, authentication_result="success").exists()
                 or IssuedCredential.objects.filter(organization=org).exists()))


def name_key(name):
    """How two organization names are compared: NFKC, case-folded, and only
    the letters and digits kept, so "Alpha Clinic", "ALPHA  CLINIC.", a
    fullwidth spelling and "alpha clinic" are one name. The signer compares
    certified names the same way (signer/registry.py, `name_key`); a test
    keeps the two in step. A database's case-insensitive match is not
    enough: SQLite folds only ASCII."""
    folded = unicodedata.normalize("NFKC", name or "").casefold()
    return "".join(ch for ch in folded if ch.isalnum())


#: Scripts whose letters pass for one another (signer/registry.py has the
#: same list).
CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK", "ARMENIAN",
                                "CHEROKEE", "COPTIC"})


def mixed_script(name):
    """Does `name` mix letters of look-alike scripts -- a Cyrillic or Greek
    capital A in a Latin name?"""
    seen = set()
    for ch in unicodedata.normalize("NFKC", name or ""):
        if ch.isalpha():
            script = unicodedata.name(ch, "?").split(" ")[0]
            if script in CONFUSABLE_SCRIPTS:
                seen.add(script)
    return len(seen) > 1


#: Why a name mixing scripts is refused, in words for whoever typed it.
MIXED_SCRIPT_MESSAGE = (
    "An organization name may not mix letters of look-alike scripts, such as "
    "a Cyrillic or Greek letter in a Latin name: on a phone it would read as "
    "another organization's.")


def problem(name, org):
    """Why `name` may not be `org`'s, or "": it mixes look-alike scripts, or
    another organization already has it in some spelling. Every page that
    names an organization asks this."""
    if mixed_script(name):
        return MIXED_SCRIPT_MESSAGE
    key = name_key(name)
    if key:
        others = Organization.objects.only("name")
        if org is not None and org.pk is not None:
            others = others.exclude(pk=org.pk)
        for other in others:
            if name_key(other.name) == key:
                return f"An organization named '{other.name}' already exists."
    return ""


def locked_for(org, site_admin):
    """Is renaming `org` refused to somebody who is (not) a site admin?"""
    return not site_admin and has_issued(org)


def log_rename(actor, org, old, new):
    """One line per rename, naming who made it. `actor` is a User, a user
    id, or a label such as "django:3"."""
    if (old or "") != (new or ""):
        logger.warning("Organization %s renamed by user %s: %r -> %r",
                       org.pk, getattr(actor, "pk", actor), old or "", new or "")

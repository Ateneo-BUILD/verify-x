"""User Records: a verified person's earlier transactions, in every organization.

After a successful verification the document page lists what has been logged
for the same person before -- when, which organization, the transaction type,
and the operator who handled it -- when the operating organization has
`Organization.check_user_records` on. Three rules hold it together.

**The person is a key, not a number.** `Transaction.subject_key` is a keyed
hash of the card number (or, lacking one, the digital ID), so the column
names nobody: it cannot be reversed without this server's key, and it is not
a value anybody could type into a search box. It is written on every
successful row WHATEVER the organization's field settings say. "Log" off for
the ID number columns means the number is not kept -- it does not mean the
person should become unfindable -- and matching on the stored columns would
have silently lost every organization that switched them off.

**The person comes only from what eVerify returned, in this session.** The
key is computed from the upstream's own answer in `everify_query_api()` and
kept with that answer by `accounts.verified_answer`, bound to the
organization that asked. It is never taken from the request: a lookup keyed
on anything the browser sent would let any operator read anybody's history
by typing a number. That is the identity rule from sign-in -- the identity
comes only from what the upstream returned (`_login_user_from_everify()`) --
applied to the person being verified rather than the person verifying.

**Successful rows only.** A failed attempt may not have been the cardholder
at all, and listing it under their name would say otherwise.

**Repeats are split between the server and the page.** Whether a row was
logged HERE, inside the organization's window, with the alert on, is decided
here (`counts_as_repeat`), by organization id. Whether its TYPE is the one
being logged is the page's question, because the type is picked there before
anything is logged and the answer has to follow the picker.
"""

import datetime
import logging
import re

from django.conf import settings
from django.utils import timezone
from django.utils.crypto import salted_hmac

from accounts import everify_fields
from accounts.models import Transaction, UserRecordsRead

logger = logging.getLogger(__name__)

#: Separates this use of the key from every other. Part of the stored value:
#: changing it orphans every key already written.
SALT = "verify.user-records.subject.v1"

#: The page is sent at most this many, newest first, and told when there were
#: more. Searching and paging happen in the browser, over what it was sent.
MAX_RECORDS = 1000

#: The longest repeat-alert window an organization may set, in days. Ten
#: years; anything longer is "any time", which 0 already says.
MAX_REPEAT_ALERT_DAYS = 3650

#: What another organization's row says in place of a type it keeps to itself.
TYPE_NOT_SHARED = "Not shared"


def _secret():
    """USER_RECORDS_KEY, or SECRET_KEY when it is not set. See settings."""
    return settings.USER_RECORDS_KEY or settings.SECRET_KEY


def subject_key(card_number="", digital_id=""):
    """The key for one person, or "" when there is nothing to key on.

    The card number wins when there is one: it is the number the person is
    known by on every path that reaches this app. Dashes and spaces are not
    part of it -- the same card is typed both ways.
    """
    digits = re.sub(r"\D", "", str(card_number or ""))
    if len(digits) == 16:
        basis = "pcn:" + digits
    else:
        code = re.sub(r"\s", "", str(digital_id or "")).upper()
        if not code:
            return ""
        basis = "did:" + code
    return salted_hmac(SALT, basis, secret=_secret(),
                       algorithm="sha256").hexdigest()


def subject_from_raw(data):
    """From eVerify's raw `data` object, before any field configuration."""
    data = data or {}
    return subject_key(data.get("reference"), data.get("code"))


def subject_from_rows(rows):
    """From verification rows, matched by eVerify's own key, never the label."""
    values = {}
    for row in rows or ():
        field = everify_fields.field_of(row)
        if field in ("reference", "code"):
            values[field] = row.get("value")
    return subject_key(values.get("reference"), values.get("code"))


def records_for(key, limit=None):
    """(transactions, truncated): the person's successful rows, newest first."""
    if limit is None:
        limit = MAX_RECORDS
    if not key:
        return [], False
    rows = list(Transaction.objects
                .filter(subject_key=key, authentication_result="success")
                .select_related("organization", "operator",
                                "transaction_type_ref")
                .order_by("-verification_timestamp", "-id")[:limit + 1])
    return rows[:limit], len(rows) > limit


def record_read(operator, org, key, count):
    """Leave the trace a read of `key`'s history leaves: who, for which
    organization, whose (the key, never a number) and how many rows. Logged
    as well, so it reaches the journal."""
    UserRecordsRead.objects.create(operator=operator, organization=org,
                                   subject_key=key, records=count)
    logger.info("User Records: user %s read %d records for organization %s",
                getattr(operator, "pk", None), count, getattr(org, "pk", None))


def type_shown(txn, viewer):
    """May `viewer`'s operators see the type of `txn`?

    Always for their own organization's rows, and for a holder's
    self-verification, which belongs to no organization. Another
    organization's, only when it shares the type: a type is the
    organization's own category, and some name things a person would not
    want every organization to know. A type deleted since leaves nothing to
    say whether it was shared, so it is not named: deleting a type it had
    kept to itself must not hand its name back to everybody. Every
    verification since migration 0010 links its type, so a row with no link
    is one whose type is gone."""
    if viewer is not None and txn.organization_id == viewer.id:
        return True
    if txn.organization_id is None:
        return True
    ref = txn.transaction_type_ref
    return ref is not None and ref.shared_in_user_records


def repeat_window(org, now=None):
    """(on, since) for `org`'s repeat alert.

    `on` is False when the organization has switched it off. `since` is the
    earliest moment an earlier transaction still counts, or None when the
    window is 0 days -- any time.
    """
    if not org.repeat_alert:
        return False, None
    days = org.repeat_alert_days or 0
    if days <= 0:
        return True, None
    return True, (now or timezone.now()) - datetime.timedelta(days=days)


def counts_as_repeat(txn, org, on, since, current=""):
    """Whether `txn` raises the repeat alert, should its type be the one picked.

    HERE is the organization's id, never its name: two organizations can share
    a name, and a deleted organization's rows have none. The row just logged
    (`current`) is not a repeat of itself.
    """
    if not on or txn.organization_id != org.id:
        return False
    if current and str(txn.transaction_id) == current:
        return False
    return since is None or txn.verification_timestamp >= since

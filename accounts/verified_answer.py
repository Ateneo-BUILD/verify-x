"""eVerify's answer to this session's last verified lookup, kept on the server.

The verification an operator runs after signing in obeys the rule sign-in
does -- the identity comes only from what the upstream returned
(`_login_user_from_everify()`, pinned by
`accounts/tests.py::EverifyIdentitySourceTest`): the rows a document prints,
a transaction logs, a credential signs and a card carries come ONLY from what
eVerify answered, and that answer never makes a round trip through the
browser. Pinned by `accounts/tests_verified_answer.py`.

`everify_query_api()` keeps the answer here on a verified success, and only
there. The document page renders it, and `/everify/log-transaction/` logs,
signs and hands off exactly it -- whatever the request body says. The rows
never make a round trip through the browser: if they did, any signed-in
operator could post made-up identity data as a "success" and have a
credential signed for it.

**Bound to the organization that asked.** The answer was given to one
organization's eVerify client, filtered through that organization's field
list, and is that organization's to log. `rows()` and `subject()` answer
nothing for any other, so switching organization cannot carry a person
across, and User Records cannot be read about somebody verified elsewhere.

**One slot for the rows and the person.** `subject` is the User Records key
(`user_records.subject_from_raw()`) for the same answer. Two keys could be
cleared apart; one cannot.

**A key and a shape of its own.** Rows a browser wrote under the older key
(`verification_data`) are never read, so nothing a browser wrote is
trusted. `forget()` still drops them.

**When it was kept.** One answer may be logged more than once, by decision (a
lost response has to be retryable, and one person may be logged for two
transaction types). `kept_at` is what lets a log find the transactions this
answer already made -- this operator's successful rows about the same person,
here, since then -- so that once a document made from it is revoked the
answer is refused, rather than printing a fresh credential for the same
person without a new lookup. A timestamp written with the answer, and not a
list the log appends to: logging must not rewrite the session, which carries
the person's rows and face (verify/sessions.py).
"""

import datetime
import time

#: Session key. A dict: {"organization": <pk>, "rows": [...], "subject": "",
#: "kept_at": <seconds since the epoch>}.
KEY = "verified_answer"

#: What the browser-written rows and the separate User Records key were kept
#: under before. Dropped by forget(), never read.
_RETIRED_KEYS = ("verification_data", "verified_subject")


def keep(session, org, rows, subject=""):
    """Keep `rows` -- eVerify's answer, prepared -- as what `org` verified."""
    session[KEY] = {
        "organization": org.pk,
        "rows": list(rows),
        "subject": subject or "",
        "kept_at": time.time(),
    }


def forget(session):
    """Drop the answer, and anything a release before this one kept instead."""
    for key in (KEY,) + _RETIRED_KEYS:
        session.pop(key, None)


def _answer(session, org):
    answer = session.get(KEY)
    if org is None or not isinstance(answer, dict):
        return None
    if answer.get("organization") != org.pk:
        return None
    if not isinstance(answer.get("rows"), list):
        return None
    return answer


def rows(session, org):
    """The rows `org` was answered, or None when there is no such answer.

    An empty list is an answer -- an organization can switch every field off
    -- so callers ask `is None`, never falsiness.
    """
    answer = _answer(session, org)
    return None if answer is None else answer["rows"]


def kept_at(session, org):
    """When the answer `org` was given was kept, as an aware datetime, or
    None: no such answer, or one kept before this was recorded."""
    answer = _answer(session, org)
    value = answer.get("kept_at") if answer is not None else None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc)


def subject(session, org):
    """The User Records key of the person `org` was answered about, or ""."""
    answer = _answer(session, org)
    value = answer.get("subject") if answer is not None else ""
    return value if isinstance(value, str) else ""

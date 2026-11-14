"""Which eVerify fields an organization shows and records, and in what order.

THE LIST IS FIXED AND LIVES HERE. It is not discovered at runtime and it does
not grow by itself: it is the set of keys a real Tier II lookup returned,
with ``meta={'tier_level': 'Tier II', 'result_grade': 1}``. Extending it
means editing this file, which is the point -- the list is also the whitelist
that
decides what may come out of the response at all, so it should be reviewed
rather than accumulated.

A row in ``OrganizationFieldSetting`` overrides one entry for one
organization; ``rows_for()`` merges those over the defaults below, so a key
added here reaches every organization at once with no data migration.

The first thirteen are the whitelist the app already had. They keep their
place at the top, their order, their display text and their old
display/log defaults. The other twenty-three follow, switched off and
with no display text -- which is the "otherwise it will be the key name"
rule doing its job, and is why enabling one shows ``present_barangay``
until somebody types a better name. ``email``, ``mobile_number`` and
``residency_status`` are the ones that came with names, because their keys
read badly on a document.

ONE entry is not a key the lookup returned: ``age``, under the portrait. It
is worked out here from ``birth_date`` on the day of the verification (see
``COMPUTED``), shown and logged by default, and left out of the signed
credential -- an age stops being true on the holder's next birthday, and the
credential already carries the date of birth it came from. It is still in
this list because this list is what a site admin can name, switch and move.

``verified`` is deliberately NOT here. A successful lookup does not carry it
(eVerify only ever reports a failure), and the app reads it straight off the raw response as the
failure signal; it is not one of the person's attributes.
"""

import datetime

#: Fields whose value cannot be readily logged. The face is a base64 image,
#: not a value a spreadsheet column can hold, so it has no Log toggle at all
#: -- not a toggle that is off, no toggle. Enforced server-side in
#: rows_for(), so a hand-made POST cannot switch one on.
NOT_LOGGABLE = frozenset({"face_url"})

#: Fields this app works out rather than reads off the response, each with
#: the field it is worked out from. An `age` in the response itself is never
#: believed: the value is this app's own arithmetic or it is absent.
COMPUTED = {"age": "birth_date"}

#: How the document prints a date. eVerify sends YYYY-MM-DD and the birth
#: date is reprinted this way; the "as of" beside an age matches it.
DATE_FORMAT = "%m/%d/%Y"

#: (key, display text, shown by default, logged by default).
#: The thirteen the app already whitelisted, in the order the document has
#: always laid them out, and the age under the portrait.
_REFERENCE = (
    ("face_url",             "Face Photo",                 True,  False),
    ("age",                  "Age",                        True,  True),
    ("first_name",           "Given Name",                 True,  True),
    ("middle_name",          "Middle Name",                True,  True),
    ("last_name",            "Last Name",                  True,  True),
    ("reference",            "National ID Card Number",    True,  True),
    ("code",                 "Digital National ID Number", True,  True),
    ("gender",               "Sex",                        True,  True),
    ("birth_date",           "Date of Birth",              True,  True),
    ("place_of_birth",       "Place of Birth",             True,  True),
    ("marital_status",       "Marital Status",             True,  True),
    ("full_address",         "Permanent Address",          True,  False),
    ("present_full_address", "Present Address",            True,  False),
    ("blood_type",           "Blood Type",                 True,  False),
)

#: Everything else the same response carried, alphabetically as it arrived.
#: No display text and both switches off: nothing about the document or the
#: export changes until a site admin turns one on.
_ALSO_RETURNED = (
    "address_line_1", "address_line_2", "barangay", "country", "email",
    "full_name", "mobile_number", "municipality", "pob_country",
    "pob_municipality", "pob_province", "postal_code",
    "present_address_line_1", "present_address_line_2", "present_barangay",
    "present_country", "present_municipality", "present_postal_code",
    "present_province", "province", "residency_status", "suffix", "token",
)

#: The few of those that start with a name rather than their key.
_ALSO_RETURNED_NAMES = {
    "email": "Email Address",
    "mobile_number": "Mobile Number",
    "residency_status": "Residency Status",
}

EVERIFY_FIELDS = _REFERENCE + tuple(
    (key, _ALSO_RETURNED_NAMES.get(key, ""), False, False)
    for key in _ALSO_RETURNED)

FIELD_KEYS = tuple(key for key, _n, _d, _l in EVERIFY_FIELDS)

#: How many lead the list with a name and a default; the page draws its
#: divider after them.
KNOWN_COUNT = len(_REFERENCE)

#: The built-in name for a key, where there is one.
DEFAULT_NAMES = {key: name for key, name, _d, _l in EVERIFY_FIELDS}

#: What it takes for a 200 to have named somebody. Asked of the RAW response,
#: never of an organization's configuration -- an organization that has
#: switched most fields off has not thereby made every lookup a miss. It is
#: deliberately these four and not "any known key": the response also carries
#: `token`, which is present whoever it does or does not describe.
IDENTITY_KEYS = ("reference", "code", "first_name", "last_name")

#: Where a logged field lands on the Transaction row. Fields absent from this
#: map have no column of their own and are kept only in `logged_fields`.
#: `authentication_result` is not here: the OUTCOME is transaction metadata,
#: like the timestamp, and is always recorded.
TRANSACTION_COLUMNS = {
    "first_name": "given_name",
    "middle_name": "middle_name",
    "last_name": "last_name",
    "reference": "national_id_card_number",
    "code": "digital_national_id_number",
    "gender": "sex",
    "birth_date": "date_of_birth",
    "place_of_birth": "place_of_birth",
    "marital_status": "marital_status",
}

#: A logged value is truncated to this before it is stored. Nothing in the
#: response should come close now that the face cannot be logged; the cap is
#: here so that a field which unexpectedly carries a blob cannot bloat every
#: transaction row before anybody notices.
MAX_LOGGED_VALUE_CHARS = 8 * 1024


def loggable(key):
    """Can this field's value be readily written to a log column?"""
    return key not in NOT_LOGGABLE


def age_on(birth_date, today):
    """Whole years from `birth_date` to `today`, or None.

    `birth_date` is eVerify's YYYY-MM-DD, or the MM/DD/YYYY the document
    prints, which is what the mock and the samples carry. A birthday counts
    on the day itself, and 29 February on 1 March in other years. A date that
    does not parse, or lies after `today`, has no age rather than a wrong one.
    """
    text = str(birth_date or "").strip()
    for spelling in ("%Y-%m-%d", DATE_FORMAT):
        try:
            born = datetime.datetime.strptime(text, spelling).date()
            break
        except ValueError:
            continue
    else:
        return None
    if born > today:
        return None
    return (today.year - born.year
            - ((today.month, today.day) < (born.month, born.day)))


def with_computed(payload, today):
    """A raw payload plus the fields this app works out from it, as of `today`.

    A copy, keyed like the response, so every builder of rows can go on
    asking "is this key in the payload" and need not know which keys are
    arithmetic. A computed key that cannot be worked out is removed, so
    nothing upstream can supply it.
    """
    values = dict(payload or {})
    age = age_on(values.get(COMPUTED["age"]), today)
    if age is None:
        values.pop("age", None)
    else:
        values["age"] = str(age)
    return values


def as_of(today):
    """The date a computed value holds for, spelled as the document prints it."""
    return today.strftime(DATE_FORMAT)


def default_rows():
    """The field list as it stands with nothing configured.

    One order, not two: the position below drives the document rows AND the
    export columns, the latter simply skipping what is not logged.
    """
    return [
        {
            "key": key,
            "name": name,
            "display": display,
            "log": log and loggable(key),
            "position": index,
            "loggable": loggable(key),
            "known": index < KNOWN_COUNT,
            # The field it is worked out from, for a computed one; "" else.
            "computed": COMPUTED.get(key, ""),
        }
        for index, (key, name, display, log) in enumerate(EVERIFY_FIELDS)
    ]


def rows_for(organization):
    """The field list for one organization, or the defaults for no organization.

    ``None`` is the login path: ``POST /everify/`` runs before anybody has a
    session, so there is no organization whose configuration could apply, and
    the defaults are what signs an operator in. Nothing an organization
    configures may reach that path.
    """
    rows = default_rows()
    if organization is None:
        return rows

    from accounts.models import OrganizationFieldSetting

    stored = {
        row.key: row
        for row in OrganizationFieldSetting.objects.filter(
            organization=organization)
    }
    previous = None
    for row in rows:
        saved = stored.get(row["key"])
        if saved is None:
            # A key added to this list after the organization saved its own
            # order. Its default position counts places in a different list,
            # so it goes straight after the field it follows by default --
            # Age under Face Photo, wherever Face Photo was moved to. The
            # fraction only sorts; the next save writes whole positions.
            if stored and previous is not None:
                row["position"] = previous["position"] + 0.001
            previous = row
            continue
        row["name"] = saved.display_name or DEFAULT_NAMES.get(row["key"], "")
        row["display"] = saved.show_on_document
        # Not loggable is not negotiable, whatever a stored row says.
        row["log"] = saved.include_in_log and row["loggable"]
        row["position"] = saved.position
        previous = row
    return rows


def label_for(row):
    """The display name when there is one, otherwise the key itself.

    A key with no name is the normal case for the twenty-three that were
    never in the whitelist: they have to render as something, and their own
    key is the only honest answer until somebody names them.
    """
    return row.get("name") or row["key"]


def in_order(rows):
    """Every field, in the single configured order."""
    return sorted(rows, key=lambda r: (r["position"], r["key"]))


def document_rows(rows):
    """What the verification document prints, in order."""
    return [r for r in in_order(rows) if r["display"]]


def log_rows(rows):
    """What the transaction log records, in the same order, minus the rest.

    No need to re-check `loggable` here: both producers of a row --
    default_rows() and rows_for() -- already force `log` false for a field
    whose value cannot be logged, so this would be a second copy of an
    invariant that is enforced where the rows are built.
    """
    return [r for r in in_order(rows) if r["log"]]


def processed_rows(rows):
    """Everything displayed or logged, in order.

    A field in neither set is never taken from the response at all. That is
    the point of switching both off.
    """
    return [r for r in in_order(rows) if r["display"] or r["log"]]


#: Built-in display name -> key. A session opened before rows carried
#: their key holds rows that only have the name, and that operator may be
#: mid-verification while a deploy lands. "Verified" is kept even though
#: the field is gone, so such a row still resolves.
_LEGACY_KEYS = {name: key for key, name in DEFAULT_NAMES.items() if name}
_LEGACY_KEYS["Verified"] = "verified"


def field_of(item):
    """The raw eVerify key for one carried row, of whatever vintage."""
    return item.get("field") or _LEGACY_KEYS.get(item.get("key"), "")


def normalise_rows(items):
    """Fill in what an older row is missing, so it still renders and logs.

    A row from before the field configuration has no "field" and no "show".
    Its key is recoverable from its built-in name, and it was written when
    everything whitelisted was shown -- so "show" defaults to True.
    """
    out = []
    for item in items:
        row = dict(item)
        row.setdefault("field", _LEGACY_KEYS.get(item.get("key"), ""))
        row.setdefault("show", True)
        out.append(row)
    return out

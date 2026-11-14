"""A synthetic verification result: nobody, in the shape of somebody.

There is a standing need to look at a finished verification document -- the
two symbols, the density tiers, the demo redaction, a new field switched on --
without running a real lookup against a real person. The dev store
(`debug_store`) answers the measuring half of that question and answers it
better, because it holds what the upstream actually returned. This answers the
*looking* half, and it does it with no identity record involved at all.

Two rules it keeps, and they are the reason it can be a page rather than a
fixture in a test:

**Nothing here comes from the request.** The values are constants in this
module and the face is drawn by `sample_face`. A page that could be told what
identity to render is a page that renders whatever a caller types, which is
the shape of the mock's problem -- see `_mock_everify_data()`, which echoes the
caller's own POST body back as a verified identity and needs two opt-ins for
exactly that reason. This one has nothing to echo. A caller may name a stored
capture to render instead -- see `sample_rows(values=...)` -- and that is the
same thing one level along: the *values* still come from the store rather than
from the request, and all the request chose was which stored row to open.

**It is still put through the organization's field configuration.** The rows
are built from `rows_for(organization)`, same as a real response, so the
sample document shows what *this* organization would print, in its order, under
its labels -- including the twenty-three keys that are off by default, which is
most of the reason to look at a sample at all.

Every key in `EVERIFY_FIELDS` has a value here, so switching one on has
something to show. `token` is the exception: it is an upstream credential, it
is in the list only because the response carries it, and a sample document is
not a place to demonstrate one.
"""

from __future__ import annotations

import uuid

from django.utils import timezone

from accounts import everify_fields, sample_face

#: The sample person: Lisa Rose Reyes Cruz, who goes with
#: `static/sample-id1.png`.
#:
#: The given name is TWO words, which is the ordinary case here -- MARIA
#: CLARA, JUAN PAULO -- and worth having in the sample rather than a tidy
#: single word: it is what a name field has to survive. The middle name is
#: carried because it is one of the thirteen fields shown by default and an
#: empty value drops its row; a sample that quietly exercises twelve of
#: thirteen is a worse sample.
SAMPLE_VALUES = {
    "first_name": "LISA ROSE",
    "middle_name": "REYES",
    "last_name": "CRUZ",
    "suffix": "",
    "full_name": "LISA ROSE REYES CRUZ",
    "reference": "0000-1111-2222-3333",
    "code": "SMP0001",
    "gender": "Female",
    "birth_date": "03/14/1988",
    "place_of_birth": "Quezon City, Metro Manila",
    "pob_municipality": "Quezon City",
    "pob_province": "Metro Manila",
    "pob_country": "Philippines",
    "marital_status": "Married",
    "blood_type": "AB+",
    "residency_status": "Filipino Citizen",
    "email": "sample.person@example.ph",
    "mobile_number": "+639170000000",
    # The two addresses are the longest values eVerify returns, and leaving
    # them short sizes the stamp wrong: a fixture that stops at "Place of
    # Birth" never reaches them. They stay long even
    # though the name shortened -- what the credential has to carry is set by
    # the longest values, not by the name.
    "full_address": "1226 Sampaguita Street, Barangay Malinis, "
                    "Quezon City, Metro Manila 1100",
    "address_line_1": "1226 Sampaguita Street",
    "address_line_2": "Unit 4B, Villanueva Apartments",
    "barangay": "Barangay Malinis",
    "municipality": "Quezon City",
    "province": "Metro Manila",
    "postal_code": "1100",
    "country": "Philippines",
    "present_full_address": "78 Katipunan Avenue Extension, Barangay Loyola "
                            "Heights, Quezon City, Metro Manila 1108",
    "present_address_line_1": "78 Katipunan Avenue Extension",
    "present_address_line_2": "Second Floor",
    "present_barangay": "Barangay Loyola Heights",
    "present_municipality": "Quezon City",
    "present_province": "Metro Manila",
    "present_postal_code": "1108",
    "present_country": "Philippines",
}


def sample_payload(drawn_face=False):
    """The synthetic person as a raw eVerify `data` object would carry them.

    Includes the face as a data URI under `face_url`, which is what
    `_prepare_data_for_frontend()` leaves behind after fetching a real one --
    the sample skips the fetch because there is no upstream to fetch from.

    `drawn_face` swaps the chosen portrait for the drawn stand-in. They are
    for different jobs and the difference is measured: see `sample_face`.
    """
    values = dict(SAMPLE_VALUES)
    values["face_url"] = sample_face.data_uri(drawn=drawn_face)
    return values


#: The transaction fields a verification has that eVerify's response does not
#: -- what was done, and where. Constants for the same reason the identity is:
#: nothing here may be steered by a request.
SAMPLE_TRANSACTION_TYPE = "Sample transaction (not logged)"
SAMPLE_LOCATION = "Sample location"

#: A stable namespace, so the same source always shows the same id. The id is
#: a real UUID and deliberately resolves to NOTHING at `/api/validate/`: a
#: sample must not be checkable, or it stops being a sample.
SAMPLE_UUID_NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


def sample_transaction_id(source="sample"):
    return uuid.uuid5(SAMPLE_UUID_NAMESPACE, str(source))


def sample_transaction(values=None, *, organization=None, operator=None,
                       when=None, source="sample"):
    """An UNSAVED `Transaction` carrying the synthetic person, or a capture.

    Returned rather than written, and never written by any caller: it exists
    to be handed to `views.core.transaction_payload()`, so a sample validation
    page renders through exactly the code the real page renders through. A
    second formatter would drift -- the dashes in the card number and the +08
    timestamp are decisions, and a sample that spells them differently is a
    sample of a page nobody has.

    `values` is a raw eVerify payload: `SAMPLE_VALUES` by default, or a stored
    capture's when somebody wants to see the page filled with what the
    upstream actually returned.
    """
    from accounts.models import Transaction

    values = values or SAMPLE_VALUES
    location = SAMPLE_LOCATION
    if organization is not None:
        first = organization.locations.first()
        if first is not None:
            location = first.name
    return Transaction(
        transaction_id=sample_transaction_id(source),
        organization=organization,
        operator=operator,
        operator_location=location,
        given_name=values.get("first_name", ""),
        middle_name=values.get("middle_name", ""),
        last_name=values.get("last_name", ""),
        national_id_card_number=values.get("reference", ""),
        digital_national_id_number=values.get("code", ""),
        verification_timestamp=when or timezone.now(),
        transaction_type=SAMPLE_TRANSACTION_TYPE,
        authentication_result="success",
    )


def sample_rows(organization=None, *, drawn_face=False, values=None):
    """The synthetic result, through one organization's field configuration.

    The same row shape `_prepare_data_for_frontend()` produces: `field` is
    eVerify's own key and is what every later decision matches on, `key` is
    the editable label the document prints. Building it any other way would
    make the sample a different thing from what a verification produces, which
    is the one property that makes it worth rendering.

    `values` is a raw eVerify payload, exactly as `sample_transaction()` takes
    one: `SAMPLE_VALUES` by default, or a stored capture's when somebody wants
    to look at a finished document carrying what the upstream actually
    returned. The face travels in it under `face_url`, because that is where
    a real payload carries it -- the store keeps it in a column of its own and
    the caller puts it back.

    It stays a payload and never a set of rows. Building the rows here is what
    makes a capture go through THIS organization's field list, in its order and
    under its labels, rather than through whatever the organization that
    captured it happened to display.
    """
    values = values if values is not None else sample_payload(
        drawn_face=drawn_face)
    today = timezone.localdate()
    values = everify_fields.with_computed(values, today)
    rows = []
    for row in everify_fields.processed_rows(
            everify_fields.rows_for(organization)):
        key = row["key"]
        if key not in values or values[key] == "":
            continue
        rows.append({
            "field": key,
            "key": everify_fields.label_for(row),
            "value": values[key],
            "show": row["display"],
        })
        if key in everify_fields.COMPUTED:
            rows[-1]["as_of"] = everify_fields.as_of(today)
    return rows

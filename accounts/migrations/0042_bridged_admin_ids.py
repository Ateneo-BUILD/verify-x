"""Shorten bridged site-admin IDs to fit their column.

A Django superuser opening /app/ is given a verify `User` whose
`national_id_card_number` is a placeholder: "ADMIN" and the Django user id.
It was written with twelve digits -- seventeen characters in a column of
sixteen. SQLite stores that without complaint; PostgreSQL refuses it, both
when the row is created and when an existing database is loaded into it.

This rewrites the values already written to "ADMIN" and eleven digits, the
form `_get_session_user()` now creates: on the `User`, and on the two
columns that copy an operator's number -- the transactions they logged
(`operator_national_id_number`) and their phones' log records
(`owner_national_id_number`), so a row still names the same person. Nothing
looks a bridged admin up by this value -- they are found by username -- so
the change is invisible to them. A `User` whose short form is somehow taken
already is left alone, and so are the copies of its number.

The reverse does nothing: the short form is valid in either direction, and
the long one is the bug.
"""

import re

from django.db import migrations

LONG = re.compile(r"^ADMIN(\d{12})$")


def shorten(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    Transaction = apps.get_model("accounts", "Transaction")
    DeviceLogEntry = apps.get_model("accounts", "DeviceLogEntry")
    for user in User.objects.filter(national_id_card_number__startswith="ADMIN"):
        long_id = user.national_id_card_number
        match = LONG.match(long_id)
        if not match or int(match.group(1)) >= 10 ** 11:
            continue
        short = "ADMIN%011d" % int(match.group(1))
        if User.objects.filter(national_id_card_number=short).exists():
            continue
        user.national_id_card_number = short
        user.save(update_fields=["national_id_card_number"])
        Transaction.objects.filter(operator_national_id_number=long_id).update(
            operator_national_id_number=short)
        DeviceLogEntry.objects.filter(owner_national_id_number=long_id).update(
            owner_national_id_number=short)


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0041_card_handoff_expiry_index"),
    ]

    operations = [
        migrations.RunPython(shorten, migrations.RunPython.noop),
    ]

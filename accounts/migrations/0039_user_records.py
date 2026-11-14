"""User Records: a verified person's transactions, found across organizations.

Two fields and a backfill:

  * `Organization.check_user_records`, ON by default -- existing
    organizations included, which is the decision: the card appears on every
    organization's document page from this deploy, and an admin switches it
    off on the Organization page;
  * `Transaction.subject_key`, the keyed hash a person's rows are found by
    (accounts/user_records.py), indexed because it is the whole query;
  * a BACKFILL of `subject_key` on every successful row that kept a card
    number or a digital ID. Rows from organizations that had "Log" off for
    both cannot be keyed -- the number was never stored, which is the point
    of switching it off -- so those stay out of everybody's list. Failed rows
    are not keyed: the list never shows them, and a failed attempt's number is
    whatever was typed, not somebody eVerify confirmed.

The backfill keys with USER_RECORDS_KEY (or SECRET_KEY) as the instance has
it when `migrate` runs. Set USER_RECORDS_KEY in the instance's .env BEFORE
deploying this if it is going to be set at all; setting it afterwards
orphans every backfilled key.

Rolling back drops both columns. Nothing else depends on them.
"""

import re

from django.conf import settings
from django.db import migrations, models
from django.utils.crypto import salted_hmac

# A copy of accounts.user_records.subject_key() as it stood when this was
# written. A migration must not import code that can change under it; the
# test suite pins that the two still agree (UserRecordsKeyTest).
SALT = "verify.user-records.subject.v1"


def subject_key(card_number="", digital_id=""):
    digits = re.sub(r"\D", "", str(card_number or ""))
    if len(digits) == 16:
        basis = "pcn:" + digits
    else:
        code = re.sub(r"\s", "", str(digital_id or "")).upper()
        if not code:
            return ""
        basis = "did:" + code
    secret = getattr(settings, "USER_RECORDS_KEY", "") or settings.SECRET_KEY
    return salted_hmac(SALT, basis, secret=secret,
                       algorithm="sha256").hexdigest()


def backfill(apps, schema_editor):
    Transaction = apps.get_model("accounts", "Transaction")
    rows = (Transaction.objects
            .filter(authentication_result="success", subject_key="")
            .exclude(national_id_card_number="", digital_national_id_number="")
            .only("id", "national_id_card_number", "digital_national_id_number"))
    batch = []
    for txn in rows.iterator():
        key = subject_key(txn.national_id_card_number,
                          txn.digital_national_id_number)
        if not key:
            continue
        txn.subject_key = key
        batch.append(txn)
        if len(batch) >= 500:
            Transaction.objects.bulk_update(batch, ["subject_key"])
            batch = []
    if batch:
        Transaction.objects.bulk_update(batch, ["subject_key"])


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0038_device_organizations"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="check_user_records",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="transaction",
            name="subject_key",
            field=models.CharField(blank=True, db_index=True, default="",
                                   max_length=64),
        ),
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]

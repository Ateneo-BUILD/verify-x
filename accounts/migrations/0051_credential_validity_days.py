"""Credential validity becomes a site setting, 30 days by default.

And every credential already issued keeps its epoch's keys on phones until it
expires (`credential_keys.keep_readable_until`), which is what lets a card issued
with a longer date go on being read. A date only ever moves on here, so there is
nothing to undo: going back leaves the keys on phones a little longer.
"""

from django.db import migrations, models
from django.db.models import Max


def keep_keys_for_issued_credentials(apps, schema_editor):
    Key = apps.get_model("accounts", "CredentialEpochKey")
    Issued = apps.get_model("accounts", "IssuedCredential")
    latest = (Issued.objects.order_by().values("epoch")
              .annotate(last=Max("expires_at")))
    for row in latest:
        Key.objects.filter(epoch=row["epoch"],
                           not_after__lt=row["last"]).update(not_after=row["last"])


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0050_device_log_mark"),
    ]

    operations = [
        migrations.AddField(
            model_name="sitesettings",
            name="credential_validity_days",
            field=models.PositiveSmallIntegerField(default=30),
        ),
        migrations.RunPython(keep_keys_for_issued_credentials,
                             migrations.RunPython.noop),
    ]

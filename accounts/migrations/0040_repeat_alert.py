"""Repeat alert: User Records warns when the same type was logged here before.

Two columns on `Organization`, both with defaults -- ON, and a window of 90
days -- so every existing organization has the alert from this deploy, and an
admin changes either on the Organization page. Nothing is backfilled: the
alert is worked out from transactions already keyed by 0039.

Rolling back drops both columns. Nothing else depends on them.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0039_user_records"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="repeat_alert",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="organization",
            name="repeat_alert_days",
            field=models.PositiveIntegerField(default=90),
        ),
    ]

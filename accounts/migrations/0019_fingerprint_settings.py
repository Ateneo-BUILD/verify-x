"""Move the fingerprint reader off the user and onto (user, organization).

The reader is a device on the workstation the operator is sitting at, so
somebody who works at two organizations has two of them. A single row per
user meant switching organization silently carried the wrong endpoint and
serial across.

Two migrations again, for the same reason as 0016-0018: this one creates the
table and copies the existing values into it, 0020 then drops the old fields.
Nobody loses a configured reader -- an operator's current settings are copied
to every organization they belong to, which is exactly right for the one
organization they have today and a sensible starting point if they gain more.
"""

import django.db.models.deletion
from django.db import migrations, models


def copy_forward(apps, schema_editor):
    UserSettings = apps.get_model("accounts", "UserSettings")
    Membership = apps.get_model("accounts", "Membership")
    FingerprintSettings = apps.get_model("accounts", "FingerprintSettings")

    for settings_row in UserSettings.objects.all():
        memberships = Membership.objects.filter(user_id=settings_row.user_id)
        for membership in memberships:
            FingerprintSettings.objects.get_or_create(
                user_id=settings_row.user_id,
                organization_id=membership.organization_id,
                defaults={
                    "auth_endpoint": settings_row.fingerprint_auth_endpoint,
                    "serial_number": settings_row.serial_number,
                },
            )


def copy_back(apps, schema_editor):
    """Fold the readers back onto the user so 0020 can be unapplied.

    Lossy where somebody had a different reader at each organization -- one
    of them has to win. The configured one is kept in preference to a
    default, which is the useful half of the information.
    """
    UserSettings = apps.get_model("accounts", "UserSettings")
    FingerprintSettings = apps.get_model("accounts", "FingerprintSettings")

    for settings_row in UserSettings.objects.all():
        rows = list(FingerprintSettings.objects.filter(user_id=settings_row.user_id))
        if not rows:
            continue
        best = next((r for r in rows if r.serial_number and r.serial_number != "0"),
                    rows[0])
        settings_row.fingerprint_auth_endpoint = best.auth_endpoint
        settings_row.serial_number = best.serial_number
        settings_row.save(update_fields=["fingerprint_auth_endpoint",
                                         "serial_number"])


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0018_scope_lookups_drop_user_role"),
    ]

    operations = [
        migrations.CreateModel(
            name="FingerprintSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("auth_endpoint", models.URLField(
                    blank=True, default="http://127.0.0.1:4501/capture",
                    max_length=500)),
                ("serial_number", models.CharField(blank=True, default="0",
                                                   max_length=20)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("organization", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="fingerprint_settings",
                    to="accounts.organization")),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="fingerprint_settings", to="accounts.user")),
            ],
            options={
                "db_table": "fingerprint_settings",
                "verbose_name_plural": "fingerprint settings",
                "unique_together": {("user", "organization")},
            },
        ),
        migrations.RunPython(copy_forward, copy_back),
    ]

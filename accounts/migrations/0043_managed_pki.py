"""Managed-PKI groundwork: signing ids, credential states, revocations.

Everything here is inert until a signer is configured (`SIGNER_SOCKET`); with
the PEM file, verify behaves exactly as without it.

- `Organization.signing_id`: added empty, filled with a fresh UUID per row,
  then made unique. A unique field with a callable default would give every
  existing row the same value.
- `IssuedCredential.state`: existing rows were all signed before they were
  written, so they are `signed`.
- `RevokedCredentialId`, and `RevocationState` seeded with its one row.
- `IssuerKey` gains the signer mirror's fields; `Device` the capability date.
"""

import uuid

import django.db.models.deletion
from django.db import migrations, models


def fill_signing_ids(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    for org in Organization.objects.filter(signing_id__isnull=True):
        org.signing_id = uuid.uuid4()
        org.save(update_fields=["signing_id"])


def seed_revocation_state(apps, schema_editor):
    RevocationState = apps.get_model("accounts", "RevocationState")
    RevocationState.objects.get_or_create(pk=1, defaults={"generation": 0})


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0042_bridged_admin_ids"),
    ]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="signing_id",
            field=models.UUIDField(editable=False, null=True),
        ),
        migrations.RunPython(fill_signing_ids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="organization",
            name="signing_id",
            field=models.UUIDField(default=uuid.uuid4, editable=False,
                                   unique=True),
        ),
        migrations.AddField(
            model_name="issuedcredential",
            name="state",
            field=models.CharField(
                choices=[("pending", "Pending"), ("signed", "Signed"),
                         ("unknown", "Unknown")],
                default="signed", max_length=8),
        ),
        migrations.CreateModel(
            name="RevokedCredentialId",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("credential_id", models.UUIDField(unique=True)),
                ("reason", models.CharField(blank=True, default="",
                                            max_length=200)),
                ("added_at", models.DateTimeField(auto_now_add=True)),
                ("added_by", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+", to="accounts.user")),
            ],
            options={"db_table": "revoked_credential_ids",
                     "ordering": ["-added_at"]},
        ),
        migrations.CreateModel(
            name="RevocationState",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("generation", models.PositiveBigIntegerField(default=0)),
            ],
            options={"db_table": "revocation_state"},
        ),
        migrations.RunPython(seed_revocation_state, migrations.RunPython.noop),
        migrations.AddField(
            model_name="issuerkey", name="source",
            field=models.CharField(default="file", max_length=8)),
        migrations.AddField(
            model_name="issuerkey", name="state",
            field=models.CharField(blank=True, default="", max_length=16)),
        migrations.AddField(
            model_name="issuerkey", name="organization_signing_id",
            field=models.UUIDField(blank=True, null=True)),
        migrations.AddField(
            model_name="issuerkey", name="certified_name",
            field=models.CharField(blank=True, default="", max_length=255)),
        migrations.AddField(
            model_name="issuerkey", name="subject",
            field=models.CharField(blank=True, default="", max_length=512)),
        migrations.AddField(
            model_name="issuerkey", name="fingerprint_sha256",
            field=models.CharField(blank=True, default="", max_length=64)),
        migrations.AddField(
            model_name="issuerkey", name="certificate_chain",
            field=models.BinaryField(blank=True, null=True)),
        migrations.AddField(
            model_name="issuerkey", name="cert_not_after",
            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(
            model_name="issuerkey", name="synced_at",
            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(
            model_name="device", name="issuer_chain_capable_at",
            field=models.DateTimeField(blank=True, null=True)),
    ]

"""Multi-organization schema.

Split into three migrations on purpose. This one only ADDS things, so it is
safe to apply on its own: the organization foreign keys arrive nullable and
`User.role` is still here. 0017 seeds one organization from the current .env
and fills those keys in; 0018 then tightens them and drops `User.role`.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0015_sitesettings"),
    ]

    operations = [
        migrations.CreateModel(
            name="Organization",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True)),
                ("subtitle", models.CharField(blank=True, default="", max_length=255)),
                ("logo_data", models.TextField(blank=True, default="")),
                ("mark_color", models.CharField(blank=True, default="#00386a", max_length=7)),
                ("everify_base_url", models.CharField(
                    blank=True, default="https://ws.everify.gov.ph/api", max_length=255)),
                ("everify_client_id", models.CharField(blank=True, default="", max_length=255)),
                ("everify_client_secret", models.CharField(blank=True, default="", max_length=255)),
                ("everify_public_api_key", models.TextField(blank=True, default="")),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "organizations", "ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="Membership",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("role", models.CharField(
                    choices=[("operator", "Operator"), ("admin", "Admin")],
                    default="operator", max_length=20)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("organization", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="memberships", to="accounts.organization")),
                ("user", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="memberships", to="accounts.user")),
            ],
            options={
                "db_table": "memberships",
                "ordering": ["organization__name", "user__last_name"],
                "unique_together": {("organization", "user")},
            },
        ),
        migrations.AddField(
            model_name="user",
            name="is_site_admin",
            field=models.BooleanField(default=False),
        ),
        # Nullable for now; 0017 fills them, 0018 makes them required.
        migrations.AddField(
            model_name="location",
            name="organization",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.CASCADE,
                related_name="locations", to="accounts.organization"),
        ),
        migrations.AddField(
            model_name="transactiontype",
            name="organization",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.CASCADE,
                related_name="transaction_types", to="accounts.organization"),
        ),
        # Site-wide uniqueness has to go before two organizations can both
        # have a "Main Office"; the per-organization constraint lands in 0018.
        migrations.AlterField(
            model_name="location",
            name="name",
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name="transactiontype",
            name="name",
            field=models.CharField(max_length=255),
        ),
        migrations.AddField(
            model_name="transaction",
            name="organization",
            field=models.ForeignKey(
                blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                related_name="transactions", to="accounts.organization"),
        ),
        migrations.AddField(
            model_name="transaction",
            name="acting_as_site_admin",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="sitesettings",
            name="everify_base_url",
            field=models.CharField(blank=True, default="https://ws.everify.gov.ph/api",
                                   max_length=255),
        ),
        migrations.AddField(
            model_name="sitesettings",
            name="everify_client_id",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="sitesettings",
            name="everify_client_secret",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="sitesettings",
            name="everify_public_api_key",
            field=models.TextField(blank=True, default=""),
        ),
    ]

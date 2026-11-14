"""Tighten what 0017 filled in, and retire the site-wide role column.

`User.role` cannot survive multi-tenancy: the same person is routinely an
admin at one organization and an operator at another. Its replacement is
Membership.role, written by 0017 before this runs.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0017_seed_first_organization"),
    ]

    operations = [
        migrations.AlterField(
            model_name="location",
            name="organization",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="locations", to="accounts.organization"),
        ),
        migrations.AlterField(
            model_name="transactiontype",
            name="organization",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="transaction_types", to="accounts.organization"),
        ),
        migrations.AlterUniqueTogether(
            name="location",
            unique_together={("organization", "name")},
        ),
        migrations.AlterUniqueTogether(
            name="transactiontype",
            unique_together={("organization", "name")},
        ),
        migrations.RemoveField(
            model_name="user",
            name="role",
        ),
    ]

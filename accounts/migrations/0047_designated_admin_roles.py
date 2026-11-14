"""Who designated an eVerify sign-in a site admin or admin of every
organization, and when (accounts/admin_roles.py).

Two nullable columns; nothing existing changes, and no row is designated by
this.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0046_site_admins_are_superusers'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='admin_role_granted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='admin_role_granted_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='accounts.user'),
        ),
    ]

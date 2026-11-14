"""Record who granted a person's phones the restricted tier, and when.

The restricted tier opens every organization's documents, because epoch keys
are site-wide. So it is a site administrator's to hand out, not an
organization admin's, and each grant is kept: who made it and when. Rows
granted before this migration carry no record -- 0030 granted the tier to
every member at once -- and say so where they are listed.

Adding the two columns changes nobody's tier.
"""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0043_managed_pki'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='restricted_tier_granted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='restricted_tier_granted_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='accounts.user'),
        ),
    ]

"""Count requests per client address, for the limits on what anybody can
reach without signing in (accounts/throttle.py).

A new, empty table: nothing existing changes. Only a request within its
limit writes a row, and old rows are pruned as new ones arrive.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0044_restricted_tier_grants'),
    ]

    operations = [
        migrations.CreateModel(
            name='RateLimitHit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scope', models.CharField(max_length=32)),
                ('key', models.CharField(max_length=64)),
                ('at', models.DateTimeField()),
            ],
            options={
                'db_table': 'rate_limit_hits',
                'indexes': [models.Index(fields=['scope', 'key', 'at'], name='rate_limit__scope_de5593_idx'), models.Index(fields=['at'], name='rate_limit__at_ba6fdb_idx')],
            },
        ),
    ]

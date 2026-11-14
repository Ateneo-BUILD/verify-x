"""Index `card_handoffs.expires_at`, the column every purge filters on.

`handoff.purge_expired()` runs on every hand-off it opens, and filters on
this column alone. Unindexed, each purge reads the whole table -- every
hand-off of the last five minutes -- so the cost of one verification grew
with how many other verifications had just happened. Indexed, it reads only
the rows it deletes.

Additive: rolling back drops the index and nothing else.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0040_repeat_alert"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cardhandoff",
            name="expires_at",
            field=models.DateTimeField(db_index=True),
        ),
    ]

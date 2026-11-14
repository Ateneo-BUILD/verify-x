"""Two things the dev store was missing: a switch, and the failures.

The switch is on `SiteSettings` and defaults ON, so an instance with the
environment gate open goes on capturing as it was. It can only turn
the store off -- `debug_store.capture_enabled()` reads it behind
`debug_allowed()`, never instead of it.

The three columns on `DebugCapture` let a lookup that produced no identity be
kept beside the ones that did. Existing rows are successes: nothing that
failed was ever written, which is the gap this closes.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0031_debug_captures"),
    ]

    operations = [
        migrations.AddField(
            model_name="sitesettings",
            name="debug_capture_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="debugcapture",
            name="outcome",
            field=models.CharField(default="success", max_length=16),
        ),
        migrations.AddField(
            model_name="debugcapture",
            name="status_code",
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="debugcapture",
            name="detail",
            field=models.CharField(blank=True, default="", max_length=200),
        ),
    ]

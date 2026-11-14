"""Drop the per-user fingerprint fields now that 0019 has copied them out.

UserSettings keeps demo_mode, which is genuinely a property of the operator
rather than of the desk they are sitting at.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0019_fingerprint_settings"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="usersettings",
            name="fingerprint_auth_endpoint",
        ),
        migrations.RemoveField(
            model_name="usersettings",
            name="serial_number",
        ),
    ]

"""Give every location a short code for the offline credential.

`Location.name` is a 255-character field, and it was feeding the credential's
issuer_location claim directly -- an unbounded value on a QR payload already
at the limit of what a printed stamp can carry. The code is capped at six.

Seeded from the name's initials, deduplicated within each organization: two
organizations will both want a "Main Office", exactly as they both want the
name. Hand-written because makemigrations cannot seed, and because the
dedupe has to happen per organization rather than globally.
"""

import re

from django.db import migrations, models


def _suggest(name):
    words = [w for w in name.replace("-", " ").split() if w[:1].isalnum()]
    if not words:
        base = "LOC"
    elif len(words) == 1:
        base = words[0][:6].upper()
    else:
        base = "".join(w[0] for w in words[:6]).upper()
    return re.sub(r"[^A-Z0-9]", "", base)[:6] or "LOC"


def seed_codes(apps, schema_editor):
    Location = apps.get_model("accounts", "Location")
    by_org = {}
    for row in Location.objects.order_by("organization_id", "id"):
        taken = by_org.setdefault(row.organization_id, set())
        base = _suggest(row.name)
        code, suffix = base, 2
        while code in taken:
            code = "%s%d" % (base[:6 - len(str(suffix))], suffix)
            suffix += 1
        taken.add(code)
        row.code = code
        row.save(update_fields=["code"])


def clear_codes(apps, schema_editor):
    apps.get_model("accounts", "Location").objects.update(code="")


class Migration(migrations.Migration):

    dependencies = [("accounts", "0024_organization_issuer_code")]

    operations = [
        migrations.AddField(
            model_name="location",
            name="code",
            field=models.CharField(blank=True, default="", max_length=6),
        ),
        migrations.RunPython(seed_codes, clear_codes),
    ]

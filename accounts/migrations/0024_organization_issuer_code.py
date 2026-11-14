"""Give every organization a short issuer code for offline credentials.

Seeded from the initials already used for the fallback logo mark, so an
existing deployment gets a sensible code without anybody typing one -- PSA for
"Philippine Statistics Authority". From then on it is stored and edited, never
re-derived: the code is signed into credentials that outlive a rename.

Written by hand rather than by makemigrations because the unique constraint
needs the data populated first, and initials collide -- two organizations
whose names reduce to the same letters have to be told apart before the
constraint is applied, not after it fails.
"""

import re

from django.db import migrations, models


def _initials(name):
    """The same rule as Organization.initials, duplicated on purpose.

    A migration must not call model properties: this one has to keep producing
    what it produced on the day it ran, whatever that property becomes later.
    """
    words = [w for w in name.replace("-", " ").split() if w[:1].isalnum()]
    if not words:
        return "ORG"
    if len(words) == 1:
        return words[0][:3].upper()
    return "".join(w[0] for w in words[:3]).upper()


def seed_codes(apps, schema_editor):
    Organization = apps.get_model("accounts", "Organization")
    taken = set()
    for org in Organization.objects.order_by("id"):
        base = re.sub(r"[^A-Z0-9]", "", _initials(org.name))[:8] or "ORG"
        code = base
        suffix = 2
        while code in taken:
            # Keep it inside 8 characters while it stays unique.
            code = "%s%d" % (base[:8 - len(str(suffix))], suffix)
            suffix += 1
        taken.add(code)
        org.issuer_code = code
        org.save(update_fields=["issuer_code"])


def clear_codes(apps, schema_editor):
    apps.get_model("accounts", "Organization").objects.update(issuer_code=None)


class Migration(migrations.Migration):

    dependencies = [("accounts", "0023_one_field_order")]

    operations = [
        # Added without the constraint, populated, then constrained -- the
        # order matters on a database that already has organizations.
        migrations.AddField(
            model_name="organization",
            name="issuer_code",
            field=models.CharField(blank=True, default=None, max_length=8,
                                   null=True),
        ),
        migrations.RunPython(seed_codes, clear_codes),
        migrations.AlterField(
            model_name="organization",
            name="issuer_code",
            field=models.CharField(blank=True, default=None, max_length=8,
                                   null=True, unique=True),
        ),
    ]

"""Collapse the two field orders into one.

0022 gave each field a document_order and a log_order, edited in two
side-by-side lists. One list is easier to read than that flexibility was
worth, so there is now a single position driving both the document rows and
the export columns.

The document order is what is kept: it is the order laid out for the person
holding the printed page, whereas the CSV's order only ever mattered to
whoever opened the file. Written by hand rather than by makemigrations, which
cannot tell a rename from a drop-and-add and would have discarded any
ordering an organization had already set.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0022_transaction_logged_fields_organizationfieldsetting"),
    ]

    operations = [
        migrations.RenameField(
            model_name="organizationfieldsetting",
            old_name="document_order",
            new_name="position",
        ),
        migrations.RemoveField(
            model_name="organizationfieldsetting",
            name="log_order",
        ),
        migrations.AlterField(
            model_name="organizationfieldsetting",
            name="position",
            field=models.IntegerField(default=0),
        ),
        migrations.AlterModelOptions(
            name="organizationfieldsetting",
            options={"ordering": ["organization", "position"]},
        ),
    ]

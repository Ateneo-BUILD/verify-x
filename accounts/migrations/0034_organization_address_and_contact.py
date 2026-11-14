"""Postal address and a contact person for an organization.

Nine columns, every one optional and defaulting to "". An existing deployment
sees no change: nothing reads them until somebody fills them in, and nothing
refuses to save without them -- a required field here would have stopped an
admin editing an eVerify client until they went and found a postal code.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("accounts", "0033_card_handoffs")]

    operations = [
        migrations.AddField(
            model_name="organization",
            name="address_line1",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="organization",
            name="address_line2",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="organization",
            name="barangay",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="organization",
            name="municipality",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="organization",
            name="postal_code",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
        migrations.AddField(
            model_name="organization",
            name="country",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="organization",
            name="contact_person",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="organization",
            name="contact_email",
            field=models.EmailField(blank=True, default="", max_length=254),
        ),
        migrations.AddField(
            model_name="organization",
            name="contact_mobile",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
    ]

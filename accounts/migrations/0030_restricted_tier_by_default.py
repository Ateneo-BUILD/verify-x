"""An organization's own operators read the holder's details by default.

`User.device_restricted_tier` decides whether somebody's paired phones may
decrypt the restricted tier of a credential -- the holder's name, birth date
and ID numbers -- or only confirm the document is genuine. Off by default
would treat confirming genuineness as the job and reading the person out of
it as the exception, which is wrong about whose phones these are. They
belong to an organization's own operators, checking a document against the
person holding it, and a verifier that cannot show the name it has just
validated cannot make that comparison at all. Somebody trusted to run the
verification on the web is already reading the same fields there.

Two parts, and they are not the same thing:

  * the field default flips, so anybody added from now on has it;
  * existing people are granted it -- otherwise the change means nothing on
    a deployment that already has its operators, which is every deployment.

The backfill is scoped to people with a MEMBERSHIP. "Organization user" is
who this is for, and somebody who belongs to no organization is not one.
They can still reach the Devices page and pair a phone, so this is not
academic; an admin can grant it on the user if they should have it.

Rolling back sets EVERY user's flag off, which is exactly the state before
this ran -- nobody had it. That discards a grant made in between, and that is
the right direction for a reverse to fail.
"""

from django.db import migrations, models


def grant_to_members(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    Membership = apps.get_model("accounts", "Membership")
    User.objects.filter(
        pk__in=Membership.objects.values("user_id")
    ).update(device_restricted_tier=True)


def withdraw_from_everyone(apps, schema_editor):
    """Fail closed: back to the state this migration found."""
    User = apps.get_model("accounts", "User")
    User.objects.update(device_restricted_tier=False)


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0029_device_tickets"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="device_restricted_tier",
            field=models.BooleanField(default=True),
        ),
        migrations.RunPython(grant_to_members, withdraw_from_everyone),
    ]

"""Generalise the pairing code into a ticket for one management operation.

A QR that carried a key bundle would work in a demo and stop working in its
second year; so every management operation -- pairing, re-keying, syncing --
is handed to a phone the same way instead: a short code naming the operation,
and an address to bring it to. `EnrolmentCode` only ever authorised one of
those three, and the name said so.

RenameModel, not a new table: the rows are a record of which phones were
paired and when, and they are worth keeping. Existing rows take the default
purpose, `enrol`, which is what every one of them actually was.
"""

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0028_devices_and_issuer_keys"),
        # Not decoration. `RenameModel` renames the model's ContentType row
        # too, and the reverse of that looks `contenttypes` up in the
        # MIGRATION STATE's app registry rather than the global one. Without
        # this edge in the graph, `migrate accounts 0028` -- the shape a
        # rollback uses -- dies with "No installed app with label
        # 'contenttypes'" after doing nothing. Forward is unaffected, so the
        # failure only ever shows up on the day somebody needs to roll back.
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.RenameModel(
            old_name="EnrolmentCode",
            new_name="DeviceTicket",
        ),
        migrations.AlterModelTable(
            name="deviceticket",
            table="device_tickets",
        ),
        migrations.AddField(
            model_name="deviceticket",
            name="purpose",
            field=models.CharField(
                choices=[("enrol", "Pair a new phone"),
                         ("rekey", "Replace a phone's key"),
                         ("sync", "Refresh a phone's keys")],
                default="enrol", max_length=16),
        ),
        migrations.AlterField(
            model_name="deviceticket",
            name="device",
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="tickets", to="accounts.device"),
        ),
        migrations.AlterField(
            model_name="deviceticket",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="device_tickets", to="accounts.user"),
        ),
        migrations.AlterModelOptions(
            name="deviceticket",
            options={"ordering": ["-created_at"]},
        ),
    ]

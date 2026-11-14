"""Phones work for organizations, and their log records say which.

From here a phone is LINKED to the organizations it works for
(`DeviceOrganization`), the app offers those in a chooser after unlock, and
every activity-log record names the one chosen -- which is what lets an
organization's admin export what its phones did for it, and nothing they did
for another.

Three things, and the third is the one that matters on a live deployment:

  * `DeviceOrganization`, with at most one CURRENT link per phone and
    organization; ending a link sets `unlinked_at` and never deletes the row;
  * `DeviceTicket.organizations` (what a pairing starts linked to) and the
    log entry's organization, its name, and the id the record claimed;
  * a BACKFILL. Every phone already paired works for every organization its
    owner belongs to -- that is simply true today, since nothing narrowed it
    -- so each one not revoked and not capped at the public tier is linked to
    every ACTIVE organization its owner is a member of. Without it every
    existing phone would wake up working for nobody, and the chooser would
    be empty on the whole fleet until somebody visited the Devices page.

Not linked by the backfill, deliberately:
  * revoked phones -- they sync nothing, so a link would never be sent;
  * `public_tier_only` phones -- registered from idmanager by a HOLDER, who
    is not working for any organization at all;
  * a site admin's phone to organizations they are not a member of. Entering
    any organization is a site admin's capability, not where they work; they
    tick the ones they mean on the Devices page.

`linked_by` is null on these rows: nobody chose them.

Rolling back does nothing of its own: reversing the operations below drops
the table, and with it every link, backfilled or not. A reverse that also
tried to delete "the backfilled ones" would have nothing left to delete.
"""

import django.db.models.deletion
from django.db import migrations, models


def link_existing_devices(apps, schema_editor):
    """Link every live, non-holder phone to its owner's active organizations.

    Skips a link that already exists, so running it twice -- or over a
    database where somebody has already linked a phone -- adds nothing and
    cannot trip the one-current-link constraint.
    """
    Device = apps.get_model("accounts", "Device")
    DeviceOrganization = apps.get_model("accounts", "DeviceOrganization")
    Membership = apps.get_model("accounts", "Membership")

    organizations = {}
    for user_id, org_id in (Membership.objects
                            .filter(organization__is_active=True)
                            .values_list("user_id", "organization_id")):
        organizations.setdefault(user_id, []).append(org_id)

    current = set(DeviceOrganization.objects
                  .filter(unlinked_at__isnull=True)
                  .values_list("device_id", "organization_id"))
    links = []
    for device_pk, owner_id in (Device.objects
                                .filter(revoked_at__isnull=True,
                                        public_tier_only=False)
                                .values_list("pk", "owner_id")):
        for org_id in organizations.get(owner_id, ()):
            if (device_pk, org_id) not in current:
                links.append(DeviceOrganization(device_id=device_pk,
                                                organization_id=org_id))
    DeviceOrganization.objects.bulk_create(links)


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0037_device_activity_log'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicelogentry',
            name='claimed_organization_id',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='devicelogentry',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='device_log_entries', to='accounts.organization'),
        ),
        migrations.AddField(
            model_name='devicelogentry',
            name='organization_name',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='deviceticket',
            name='organizations',
            field=models.ManyToManyField(blank=True, related_name='device_tickets', to='accounts.organization'),
        ),
        migrations.CreateModel(
            name='DeviceOrganization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('linked_at', models.DateTimeField(auto_now_add=True)),
                ('unlinked_at', models.DateTimeField(blank=True, null=True)),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='organization_links', to='accounts.device')),
                ('linked_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='accounts.user')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='device_links', to='accounts.organization')),
                ('unlinked_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='accounts.user')),
            ],
            options={
                'db_table': 'device_organizations',
                'ordering': ['-linked_at'],
                'constraints': [models.UniqueConstraint(condition=models.Q(('unlinked_at__isnull', True)), fields=('device', 'organization'), name='device_organization_one_current_link')],
            },
        ),
        # Nothing to undo by hand: the table goes with the reverse of
        # CreateModel above, which runs after this.
        migrations.RunPython(link_existing_devices, migrations.RunPython.noop),
    ]

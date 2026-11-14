"""User Records leaves a trace, and an organization may keep a type to itself.

A table recording every look at a person's User Records, and a switch per
transaction type, on for every existing type, so nothing anybody sees
changes until an organization turns one off. Nothing existing is rewritten.
"""

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0047_designated_admin_roles'),
    ]

    operations = [
        migrations.AddField(
            model_name='transactiontype',
            name='shared_in_user_records',
            field=models.BooleanField(default=True),
        ),
        migrations.CreateModel(
            name='UserRecordsRead',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subject_key', models.CharField(blank=True, default='', max_length=64)),
                ('records', models.PositiveIntegerField(default=0)),
                ('read_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('operator', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='accounts.user')),
                ('organization', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='accounts.organization')),
            ],
            options={
                'db_table': 'user_records_reads',
                'ordering': ['-read_at'],
            },
        ),
    ]

"""Record sign-in attempts that never reached eVerify, face included.

Purely additive, and nothing existing reads the table -- an instance that
applies this and is then rolled back loses only the attempt log. Reversing it
DROPS the captured faces, which for this table is a feature rather than a
hazard: see LoginAttempt in accounts/models.py.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0020_drop_user_fingerprint_fields'),
    ]

    operations = [
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('submitted_id', models.CharField(blank=True, default='', max_length=32)),
                ('id_kind', models.CharField(blank=True, default='other', max_length=16)),
                ('photo_data', models.TextField(blank=True, default='')),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'login_attempts',
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['submitted_id'], name='login_attem_submitt_d94c7c_idx')],
            },
        ),
    ]

"""The job queue and the nonces of a credential signer that dials out.

Both tables are empty and unused unless `SIGNER_QUEUE_KEY` is set
(`accounts.signer_queue`; signer/deploy/README.md, "Poll mode"), and empty
in the steady state when it is: a job is deleted once read, a nonce a few
minutes after its request. Nothing to carry when going back.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0051_credential_validity_days'),
    ]

    operations = [
        migrations.CreateModel(
            name='SignerNonce',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nonce', models.CharField(max_length=64, unique=True)),
                ('seen_at', models.DateTimeField(db_index=True)),
            ],
            options={
                'db_table': 'signer_nonces',
            },
        ),
        migrations.CreateModel(
            name='SignerJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('request', models.TextField()),
                ('created_at', models.DateTimeField()),
                ('expires_at', models.DateTimeField(db_index=True)),
                ('claimed_at', models.DateTimeField(blank=True, null=True)),
                ('claim', models.CharField(blank=True, db_index=True, default='', max_length=32)),
                ('answer', models.TextField(blank=True, default='')),
                ('answered_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'signer_jobs',
                'indexes': [models.Index(fields=['claimed_at', 'expires_at'], name='signer_jobs_pending')],
            },
        ),
    ]

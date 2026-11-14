"""Which signer polled: the instance id each poll names, kept with its nonce.

Setup warns when two different signers poll within minutes
(`signer_queue.pollers`). Empty for every row before, and for answers.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0052_signer_queue'),
    ]

    operations = [
        migrations.AddField(
            model_name='signernonce',
            name='signer',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
    ]

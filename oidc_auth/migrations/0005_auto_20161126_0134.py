# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_auth', '0004_nonce_state_data'),
    ]

    operations = [
        migrations.AlterField(
            model_name='openidprovider',
            name='issuer',
            field=models.URLField(),
        ),
        migrations.AlterUniqueTogether(
            name='openidprovider',
            unique_together=set([('issuer', 'client_id')]),
        ),
        migrations.RemoveField(
            model_name='nonce',
            name='issuer_url',
        ),
        migrations.AddField(
            model_name='nonce',
            name='provider_id',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
    ]

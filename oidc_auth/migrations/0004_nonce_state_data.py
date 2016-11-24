# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_auth', '0003_add_session_id_and_created'),
    ]

    operations = [
        migrations.AddField(
            model_name='nonce',
            name='state_data',
            field=models.CharField(max_length=255, null=True, blank=True),
        ),
    ]

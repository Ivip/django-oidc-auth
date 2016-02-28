# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_auth', '0002_delete_openiduser'),
    ]

    operations = [
        migrations.AddField(
            model_name='nonce',
            name='created',
            field=models.DateTimeField(default=datetime.datetime(2016, 2, 28, 5, 40, 41, 496670), auto_now_add=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='nonce',
            name='session_id',
            field=models.CharField(default='', max_length=128),
            preserve_default=False,
        ),
    ]

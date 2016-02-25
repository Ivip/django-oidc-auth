# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_auth', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='openiduser',
            name='issuer',
        ),
        migrations.RemoveField(
            model_name='openiduser',
            name='user',
        ),
        migrations.DeleteModel(
            name='OpenIDUser',
        ),
    ]

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0016_auto_20161004_2140'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='dev_validated',
            field=models.BooleanField(default=False, verbose_name=b'Validated'),
            preserve_default=True,
        ),
    ]

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0017_device_dev_validated'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='dev_cert_req',
            field=models.TextField(default='what', verbose_name=b'CSR'),
            preserve_default=False,
        ),
    ]

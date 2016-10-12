# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0018_device_dev_cert_req'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='dev_root_reply',
            field=models.TextField(null=True, verbose_name=b'Root Server Reply'),
            preserve_default=True,
        ),
    ]

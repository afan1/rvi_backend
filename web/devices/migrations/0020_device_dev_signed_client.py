# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0019_device_dev_root_reply'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='dev_signed_client',
            field=models.TextField(null=True, verbose_name=b'Signed Client Cert'),
            preserve_default=True,
        ),
    ]

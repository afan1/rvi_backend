# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0015_auto_20151111_1943'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='dev_token',
            field=models.CharField(max_length=256, null=True, verbose_name=b'Verification Token'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='device',
            name='dev_mdn',
            field=models.CharField(default=b'default-number', max_length=256, verbose_name=b'Phone Number'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='device',
            name='dev_rvibasename',
            field=models.CharField(default=b'genivi.org', max_length=256, verbose_name=b'RVI Domain'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='device',
            name='dev_uuid',
            field=models.CharField(default=b'default-uuid', max_length=256, verbose_name=b'UUID'),
            preserve_default=True,
        ),
    ]

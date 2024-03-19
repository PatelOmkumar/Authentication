# Generated by Django 5.0.3 on 2024-03-18 05:27

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0006_rolepermission_userpermission'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='role_id',
            field=models.ForeignKey(default=4, on_delete=django.db.models.deletion.CASCADE, to='account.role'),
            preserve_default=False,
        ),
    ]

# Generated by Django 5.1.3 on 2024-12-01 17:27

import builtins
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='password',
            field=models.CharField(default=builtins.dir, max_length=100),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='customuser',
            name='id',
            field=models.UUIDField(default='3d9ca7210bee492092630f26', primary_key=True, serialize=False, unique=True),
        ),
    ]
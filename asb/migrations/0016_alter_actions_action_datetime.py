# Generated by Django 4.2.11 on 2024-08-20 13:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('asb', '0015_actions_action_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='actions',
            name='action_datetime',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

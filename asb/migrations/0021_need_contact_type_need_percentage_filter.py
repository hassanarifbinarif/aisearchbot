# Generated by Django 4.2.11 on 2024-10-01 08:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('asb', '0020_alter_need_end_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='need',
            name='contact_type',
            field=models.CharField(max_length=128, null=True),
        ),
        migrations.AddField(
            model_name='need',
            name='percentage_filter',
            field=models.IntegerField(null=True),
        ),
    ]
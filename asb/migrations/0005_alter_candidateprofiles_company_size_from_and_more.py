# Generated by Django 4.2.11 on 2024-06-13 10:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('asb', '0004_profilevisibilitytoggle_is_favourite'),
    ]

    operations = [
        migrations.AlterField(
            model_name='candidateprofiles',
            name='company_size_from',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='candidateprofiles',
            name='company_size_to',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]

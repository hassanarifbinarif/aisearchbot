# Generated by Django 4.2.11 on 2024-07-09 08:12

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('asb', '0009_savedlists_savedlistprofiles'),
    ]

    operations = [
        migrations.AlterField(
            model_name='savedlistprofiles',
            name='list',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='asb.savedlists'),
        ),
        migrations.AlterField(
            model_name='savedlistprofiles',
            name='profile',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='asb.candidateprofiles'),
        ),
    ]

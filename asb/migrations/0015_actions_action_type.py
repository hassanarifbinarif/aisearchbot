# Generated by Django 4.2.11 on 2024-08-20 09:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('asb', '0014_actions'),
    ]

    operations = [
        migrations.AddField(
            model_name='actions',
            name='action_type',
            field=models.CharField(choices=[('call', 'call'), ('text_message', 'text messages'), ('voice_email', 'voice email'), ('email', 'email'), ('note', 'note'), ('convert', 'convert')], max_length=100, null=True),
        ),
    ]

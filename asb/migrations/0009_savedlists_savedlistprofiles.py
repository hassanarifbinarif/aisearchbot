# Generated by Django 4.2.11 on 2024-07-04 11:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('asb', '0008_alter_duplicateprofiles_person_skills'),
    ]

    operations = [
        migrations.CreateModel(
            name='SavedLists',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('list_user_id', models.IntegerField()),
                ('name', models.CharField(max_length=100)),
                ('list_type', models.CharField(choices=[('recruitment', 'Recruitment'), ('prospection', 'Prospection')], default='recruitment', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='SavedListProfiles',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('list', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='asb.savedlists')),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='asb.candidateprofiles')),
            ],
        ),
    ]

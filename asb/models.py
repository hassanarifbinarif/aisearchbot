import os
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext as _
from django.dispatch import receiver
from django.conf import settings


class CustomUserManager(BaseUserManager):

    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', User.Roles.ADMIN)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)
    

class User(AbstractUser):

    class Roles(models.TextChoices):
        USER = 'user', _('User')
        ADMIN = 'admin', _('Admin')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, default=Roles.USER.value, choices=Roles.choices)
    profile_picture = models.ImageField(upload_to='profiles/', default=settings.DEFAULT_PROFILE_IMAGE, null=True, blank=True)
    username = None
    objects = CustomUserManager()


class OTP(models.Model):
    class Otp_types(models.TextChoices):
        create = 'create', 'create'
        forgot = 'forgot', 'forgot'

    email  = models.EmailField(max_length=100)
    code = models.IntegerField(null=True)
    type = models.CharField(max_length=100,null=True, choices=Otp_types.choices, blank=True)
    verification_token = models.CharField(max_length=200 , null=True)
    used = models.BooleanField(default=False, null=True)
    timeout = models.DateTimeField(null=True)
    created_at = models.DateTimeField(null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.email
    

class SharedUsers(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='shared_user_profile')
    belongs_to = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    

class CandidateProfiles(models.Model):
    full_name = models.CharField(max_length=100, null=True, blank=True)
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    headline = models.CharField(max_length=250, null=True, blank=True)
    current_position = models.CharField(max_length=250, null=True, blank=True)
    company_name = models.CharField(max_length=200, null=True, blank=True)
    person_city = models.CharField(max_length=100, null=True, blank=True)
    person_state = models.CharField(max_length=100, null=True, blank=True)
    person_country = models.CharField(max_length=100, null=True, blank=True)
    person_industry = models.CharField(max_length=150, null=True, blank=True)
    tags = models.TextField(null=True, blank=True)
    person_skills = models.TextField(null=True, blank=True)
    education_experience = models.TextField(null=True, blank=True)
    company_website = models.URLField(max_length=2000, null=True, blank=True)
    email1 = models.EmailField(null=True, blank=True)
    email2 = models.EmailField(null=True, blank=True)
    phone1 = models.CharField(max_length=50, null=True, blank=True)
    phone2 = models.CharField(max_length=50, null=True, blank=True)
    person_linkedin_url = models.URLField(max_length=2000, null=True, blank=True)
    company_size_from = models.CharField(max_length=50, null=True, blank=True)
    company_size_to = models.CharField(max_length=50, null=True, blank=True)
    current_position_2 = models.CharField(max_length=250, null=True, blank=True)
    current_company_2 = models.CharField(max_length=200, null=True, blank=True)
    previous_position_2 = models.CharField(max_length=250, null=True, blank=True)
    previous_company_2 = models.CharField(max_length=200, null=True, blank=True)
    previous_position_3 = models.CharField(max_length=250, null=True, blank=True)
    previous_company_3 = models.CharField(max_length=200, null=True, blank=True)
    company_city = models.CharField(max_length=100, null=True, blank=True)
    company_state = models.CharField(max_length=100, null=True, blank=True)
    company_country = models.CharField(max_length=100, null=True, blank=True)
    person_angellist_url = models.URLField(max_length=2000, null=True, blank=True)
    person_crunchbase_url = models.URLField(max_length=2000, null=True, blank=True)
    person_twitter_url = models.URLField(max_length=2000, null=True, blank=True)
    person_facebook_url = models.URLField(max_length=2000, null=True, blank=True)
    company_linkedin_url = models.URLField(max_length=2000, null=True, blank=True)
    person_image_url = models.URLField(max_length=2000, null=True, blank=True)
    company_logo_url = models.URLField(max_length=2000, null=True, blank=True)


class DuplicateProfiles(models.Model):
    full_name = models.CharField(max_length=100, null=True, blank=True)
    first_name = models.CharField(max_length=50, null=True, blank=True)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    headline = models.CharField(max_length=250, null=True, blank=True)
    current_position = models.CharField(max_length=250, null=True, blank=True)
    company_name = models.CharField(max_length=200, null=True, blank=True)
    person_city = models.CharField(max_length=100, null=True, blank=True)
    person_state = models.CharField(max_length=100, null=True, blank=True)
    person_country = models.CharField(max_length=100, null=True, blank=True)
    person_industry = models.CharField(max_length=150, null=True, blank=True)
    tags = models.TextField(null=True, blank=True)
    person_skills = models.TextField(null=True, blank=True)
    education_experience = models.TextField(null=True, blank=True)
    company_website = models.URLField(max_length=2000, null=True, blank=True)
    email1 = models.EmailField(null=True, blank=True)
    email2 = models.EmailField(null=True, blank=True)
    phone1 = models.CharField(max_length=50, null=True, blank=True)
    phone2 = models.CharField(max_length=50, null=True, blank=True)
    person_linkedin_url = models.URLField(max_length=2000, null=True, blank=True)
    company_size_from = models.CharField(max_length=50, null=True, blank=True)
    company_size_to = models.CharField(max_length=50, null=True, blank=True)
    current_position_2 = models.CharField(max_length=250, null=True, blank=True)
    current_company_2 = models.CharField(max_length=200, null=True, blank=True)
    previous_position_2 = models.CharField(max_length=250, null=True, blank=True)
    previous_company_2 = models.CharField(max_length=200, null=True, blank=True)
    previous_position_3 = models.CharField(max_length=250, null=True, blank=True)
    previous_company_3 = models.CharField(max_length=200, null=True, blank=True)
    company_city = models.CharField(max_length=100, null=True, blank=True)
    company_state = models.CharField(max_length=100, null=True, blank=True)
    company_country = models.CharField(max_length=100, null=True, blank=True)
    person_angellist_url = models.URLField(max_length=2000, null=True, blank=True)
    person_crunchbase_url = models.URLField(max_length=2000, null=True, blank=True)
    person_twitter_url = models.URLField(max_length=2000, null=True, blank=True)
    person_facebook_url = models.URLField(max_length=2000, null=True, blank=True)
    company_linkedin_url = models.URLField(max_length=2000, null=True, blank=True)
    person_image_url = models.URLField(max_length=2000, null=True, blank=True)
    company_logo_url = models.URLField(max_length=2000, null=True, blank=True)

    original_profile = models.ForeignKey(CandidateProfiles, on_delete=models.CASCADE)


# Signals


@receiver(models.signals.pre_save, sender=User)
def auto_update_file_on_change(sender, instance, **kwargs):
    if not instance.pk:
        return False
    try:
        old_image_file = sender.objects.get(pk=instance.pk).profile_picture
    except sender.DoesNotExist:
        return False
    if old_image_file and old_image_file != settings.DEFAULT_PROFILE_IMAGE:
        new_image_file = instance.profile_picture
        if not old_image_file == new_image_file:
            if os.path.isfile(old_image_file.path):
                os.remove(old_image_file.path)



@receiver(models.signals.post_delete, sender=User)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    if instance.profile_picture and instance.profile_picture != settings.DEFAULT_PROFILE_IMAGE:
        if os.path.isfile(instance.profile_picture.path):
            os.remove(instance.profile_picture.path)
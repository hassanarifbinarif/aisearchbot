from django import forms
from .models import User, SharedUsers
from django.contrib.auth.forms import UserCreationForm


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('first_name', 'last_name', 'email', 'phone_number', 'profile_picture')

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if not len(phone_number) > 10:
            raise forms.ValidationError("Phone number must be more 10 digits.")
        if User.objects.filter(phone_number=phone_number).exclude(id=self.instance.id).exists():
            raise forms.ValidationError("User with this phone number already exists")
        return phone_number


class UserChangeForm(forms.ModelForm):
    
    def __init__(self, *args, **kwargs):
        super(UserChangeForm, self).__init__(*args, **kwargs)
        self.fields['role'].widget.attrs['disabled'] = True
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'role', 'profile_picture']

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if not first_name:
            raise forms.ValidationError("First name cannot be empty.")
        return first_name

    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')
        if not last_name:
            raise forms.ValidationError("Last name cannot be empty.")
        return last_name
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This email address is already in use.")
        elif not email:
            raise forms.ValidationError("Email cannot be empty.")
        return email

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        # print(le)
        if not len(phone_number) > 10:
            raise forms.ValidationError("Phone number must be more 10 digits.")
        if User.objects.filter(phone_number=phone_number).exclude(id=self.instance.id).exists():
            raise forms.ValidationError("User with this phone number already exists")
        return phone_number

    def clean_profile_picture(self):
        profile_picture = self.cleaned_data.get('profile_picture')
        if profile_picture and profile_picture.size > 5 * 1024 * 1024:  # 5 MB
            raise forms.ValidationError("Profile picture size should be less than 5MB.")
        return profile_picture
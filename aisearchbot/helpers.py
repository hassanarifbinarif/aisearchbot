import base64
from django.utils import timezone
from datetime import timedelta
from random import randint
from django.template.loader import get_template
from django.template import Context
from asb.models import OTP, User
from django.conf import settings
from django.core.mail import EmailMultiAlternatives


def otp_number():
    return str(randint(100000, 999999))


def get_otp_verified_token(email, secret_key):
    token_str = secret_key + 'email=' + email
    token_str_bytes = token_str.encode('ascii')
    base64_bytes = base64.b64encode(token_str_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


def decrypt_token(token):
    token_str_bytes = token.encode('ascii')
    base64_bytes = base64.b64decode(token_str_bytes)
    base64_message = base64_bytes.decode('ascii')
    code, email = base64_message.split('email=')
    return code, email


def send_verification_code_email(email: str):
    secret_key = otp_number()
    verification_token = get_otp_verified_token(email=email, secret_key=secret_key)
    update_fields = {'verification_token': f'{verification_token}', 'code': f'{secret_key}', 'timeout': timezone.now() + timedelta(hours=1), 'used': False}
    update_code = OTP.objects.update_or_create(email=email, defaults=update_fields)
    if update_code:
        try:
            email_subject = 'ASB Verification Code.'
            text_content = email_subject
            text_template = get_template('email_templates/verify-code-email.html')
            context_obj = { 'verification_code': secret_key }
            template_content = text_template.render(context_obj)
            msg = EmailMultiAlternatives(email_subject, text_content, settings.EMAIL_HOST_USER, [email])
            msg.attach_alternative(template_content, 'text/html')
            msg.send()
            return verification_token
        except Exception as e:
            print(e)
            return False
            


def queryDict_to_dict(qdict):
    return {k: v[0] if len(v) == 1 else v for k, v in qdict.lists()}

def send_account_credentials_email(email: str, password: str, url: str):
    link= url
    if email and password:
        try:
            email_subject = 'ASB Account Credentials.'
            text_content = email_subject
            text_template = get_template('email_templates/account-credentials-email.html')
            context_obj = { 'link': link, 'email': email, 'password': password  }
            template_content = text_template.render(context_obj)
            msg = EmailMultiAlternatives(email_subject, text_content, settings.EMAIL_HOST_USER, [email])
            msg.attach_alternative(template_content, 'text/html')
            msg.send()
            return True
        except Exception as e:
            print(e)
            return False
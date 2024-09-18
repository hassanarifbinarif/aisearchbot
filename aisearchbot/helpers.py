import base64
from django.utils import timezone
from datetime import timedelta
from random import randint
from django.template.loader import get_template
from django.template import Context
from asb.models import OTP, CandidateProfiles, DuplicateProfiles, User
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from django.db import transaction


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


def bulk_insert_chunk(data_chunk):
    with transaction.atomic():
        try:
            CandidateProfiles.objects.bulk_create(data_chunk)
        except Exception as e:
            print(e)

def parallel_bulk_insert(data, chunk_size=1000, max_workers=4):
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(bulk_insert_chunk, chunks)

def duplicate_bulk_insert_chunk(data_chunk):
    with transaction.atomic():
        try:
            instances = [DuplicateProfiles(**data) for data in data_chunk]
            DuplicateProfiles.objects.bulk_create(instances)
        except Exception as e:
            print(e)

def parallel_duplicate_bulk_insert(data, chunk_size=1000, max_workers=4):
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(duplicate_bulk_insert_chunk, chunks)


def get_original_profile(row, lookup):
    linkedin_url = row.get('person_linkedin_url')
    email1 = row.get('email1')
    email2 = row.get('email2')
    full_name = row.get('full_name')

    if full_name and full_name in lookup['full_name']:
        return lookup['full_name'][full_name]
    if linkedin_url and linkedin_url in lookup['linkedin']:
        return lookup['linkedin'][linkedin_url]
    elif email1 and email1 in lookup['email1']:
        return lookup['email1'][email1]
    elif email1 and email1 in lookup['email2']:
        return lookup['email2'][email1]
    elif email2 and email2 in lookup['email1']:
        return lookup['email1'][email2]
    elif email2 and email2 in lookup['email2']:
        return lookup['email2'][email2]
    return None


def process_dataframe_chunk(chunk, column_map_lower, lookup):
    chunk = chunk.replace({pd.NA: None, pd.NaT: None, '': None})

    if 'person_skills' in column_map_lower.keys():
        # chunk['person_skills'] = chunk['person_skills'].apply(lambda x: x.split(',') if pd.notna(x) else None)
        chunk['person_skills'] = chunk['person_skills'].apply(lambda x: x.split(',') if pd.notna(x) and x != '' else None)
    if 'company_size_from' in column_map_lower.keys():
        chunk['company_size_from'] = pd.to_numeric(chunk['company_size_from'], errors='coerce').fillna(0).astype(int)
    if 'company_size_to' in column_map_lower.keys():
        chunk['company_size_to'] = pd.to_numeric(chunk['company_size_to'], errors='coerce').fillna(0).astype(int)

    chunk.rename(columns=column_map_lower, inplace=True)

    chunk['original_profile'] = chunk.apply(lambda row: get_original_profile(row, lookup), axis=1)

    return chunk

def process_dataframe(df, column_map_lower, lookup, max_workers=4, chunk_size=1000):
    chunks = [df[i:i + chunk_size] for i in range(0, df.shape[0], chunk_size)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        processed_chunks = list(executor.map(lambda chunk: process_dataframe_chunk(chunk, column_map_lower, lookup), chunks))

    return pd.concat(processed_chunks, ignore_index=True)


def separate_instances_chunk(chunk):
    new_instances = [
        CandidateProfiles(**row.drop(labels=['original_profile']).to_dict())
        for _, row in chunk.iterrows() if row['original_profile'] is None
    ]

    duplicate_instances = [
        {**row.drop(labels=['original_profile']).to_dict(), 'original_profile': row['original_profile']}
        for _, row in chunk.iterrows() if row['original_profile'] is not None
    ]

    return new_instances, duplicate_instances

def separate_instances(df, max_workers=4, chunk_size=1000):
    chunks = [df[i:i + chunk_size] for i in range(0, df.shape[0], chunk_size)]

    new_instances = []
    duplicate_instances = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(separate_instances_chunk, chunks))

    for new, duplicate in results:
        new_instances.extend(new)
        duplicate_instances.extend(duplicate)

    return new_instances, duplicate_instances
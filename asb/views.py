import json
import os
import operator
import time
import re
import pandas as pd
from django.template import loader
from django.db.models import Q, F, Value, IntegerField, Count, When, Case, Func, Max
from django.db.models.expressions import RawSQL, Subquery, OuterRef
from functools import reduce
from django.http import HttpResponse, JsonResponse
from aisearchbot.helpers import send_verification_code_email, send_account_credentials_email, parallel_bulk_insert, parallel_duplicate_bulk_insert, separate_instances, process_dataframe
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.forms import AuthenticationForm, AdminPasswordChangeForm, PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.shortcuts import render, redirect
from django.utils import timezone
from asb.priorities import boolean_keyword_with_job_title_or_skill, keyword_with_job_title_or_skill
from .models import Actions, CandidateProfiles, DuplicateProfiles, LocationDetails, ProfileVisibilityToggle, SavedListProfiles, SavedLists, SharedProfiles, User, OTP, SharedUsers, SavedListProfiles, Need
from .forms import UserChangeForm, CustomUserCreationForm
from django.conf import settings
from aisearchbot.decorators import super_admin_required
from django.views.decorators.csrf import csrf_exempt
from django.db.models.functions import Lower
from operator import or_
from django.forms.models import model_to_dict
from django.core import serializers

# authentication views
def super_admin_login(request):
    context ={}
    context['hide_nav_func'] =True
    form = AuthenticationForm()
    if request.method == 'POST':
        email = request.POST.get('username')
        password = request.POST.get('password')
        try:
            user = User.objects.get(email = email)
            if user is not None:
                if user.is_active:  
                    form = AuthenticationForm(request, data=request.POST)
                    if form.is_valid():
                        user = authenticate(request, email=email, password=password)
                        if user is not None and user.is_superuser:
                            login(request, user)
                            return redirect('super_admin_login_dashboard') 
                        else:
                            messages.error(request, 'You are not authorised person or may be account suspended.') 
                else:
                    messages.error(request, "Your account temporarily suspended, contact to the system's admin.")
        except Exception as e:
            print(e)
            messages.error(request,'This email is not registered.')
    context['form'] = form
    return render(request, 'abs-authentication/login.html', context)


def super_admin_logout(request):
    logout(request)
    return redirect('super_admin_login')


def send_otp(request):
    context ={}
    context['hide_nav_func'] =True
    if request.method == "POST":
        try:
            email = request.POST.get('email')
            user = User.objects.get(email=email)
            if user is None:
                messages.error(request,'This email is not registered.')
            else:
                token = send_verification_code_email(email)
                if token == False:
                    messages.error(request, 'Could not send email, retry later.')                    
                else:
                    request.session['email'] = email
                    return redirect('super_admin_login_verify_code')
        except User.DoesNotExist:
            messages.error(request, 'User with the provided email does not exist.')
        except Exception as e:
            print(e)
            messages.error(request, 'Something bad happened')
    return render(request, 'abs-authentication/forgot-password.html', context)


def verify_code(request):
    context ={}
    context['hide_nav_func'] =True
    context['email'] = request.session.get('email')

    if request.method == "POST":
       try:
        code1 = request.POST.get('code1')
        code2 = request.POST.get('code2')
        code3 = request.POST.get('code3')
        code4 = request.POST.get('code4')
        code5 = request.POST.get('code5')
        code6 = request.POST.get('code6')

        code  = code1 + code2 + code3 + code4 + code5 + code6
        otp_record = OTP.objects.get(email = context['email'])
        if otp_record is None:
                messages.error(request, 'Verification code not found.')
        elif otp_record.used == True:
                messages.error(request, 'Verification code already used.')
        elif timezone.now() > otp_record.timeout:
                messages.error(request, 'Verification code timeout.')
        elif int(code) != otp_record.code:
                messages.error(request, 'Verification code is invalid.')
        else:
            otp_record.used = True
            otp_record.save(update_fields=['used'])
            # messages.success(request, 'Verification code successfully verified')
            return redirect('super_admin_login_reset_password')
       
       except Exception as e:
           messages.error(request, 'Something bad happened')
    return render(request, 'abs-authentication/verify-code.html', context)


def reset_password(request):
    context ={}
    context['hide_nav_func'] =True
    email = request.session.get('email')
    form = None
    try:
        user = User.objects.get(email = email)
        form = AdminPasswordChangeForm(user)

        if request.method == 'POST':
            form = AdminPasswordChangeForm(data=request.POST, user=user)
            if form.is_valid():
                form.save()
                messages.success(request, 'Password is successfully Reset')
                return redirect('super_admin_login')
            print(form.errors)
    except User.DoesNotExist:
        messages.error(request, 'User with the provided email does not exist.')
    except Exception as e:
        print(e)
        messages.error(request, 'An error occurred while resetting the password.')

    context['form'] = form
    return render(request, 'abs-authentication/reset-password.html', context)


#dashboard views
@super_admin_required
@login_required(login_url='super_admin_login')
def dashboard(request):
    context={}
    context['active_sidebar'] = 'dashboard'
    return render(request, 'dashboard/listing.html', context)


@super_admin_required
@login_required(login_url='super_admin_login')
def manage_conflicts(request):
    context={}
    # duplicate_profiles = DuplicateProfiles.objects.all()
    # for duplicate in duplicate_profiles:
    #     duplicate.keep_most_recent()
    # duplicate_profiles = DuplicateProfiles.objects.all()
    # for duplicate in duplicate_profiles:
    #     duplicate.save_best_record()
    context['active_sidebar'] = 'conflicts'
    return render(request, 'dashboard/manage-conflicts.html', context)


#accounts views
@super_admin_required
@login_required(login_url='super_admin_login')
def account(request):
    context={}
    context['active_sidebar'] = 'account'
    return render(request, 'accounts/account.html', context)


@super_admin_required
@login_required(login_url='super_admin_login')
def update_personal_info(request):
    context={}
    context['active_sidebar'] = 'account'
    user = request.user
    user_form = UserChangeForm(instance=user)
    
    if request.method == 'POST':
        user_form = UserChangeForm(request.POST, request.FILES, instance=user)
        user_form_valid = user_form.is_valid()
        
        if user_form_valid:
            user_form.save()
            messages.success(request, 'Your account details were successfully updated!')
            return redirect('account')
    
    context['form'] = user_form
    return render(request, 'accounts/change-personal-info.html', context)


@super_admin_required
@login_required(login_url='super_admin_login')
def update_password(request):
    context = {}
    context['active_sidebar'] = 'account'
    user = request.user
    password_form = PasswordChangeForm(user)
    if request.method == 'POST':
        password_form = PasswordChangeForm(user, request.POST)
        password_form_valid = password_form.is_valid()

        if password_form_valid:
            user = password_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('account')

    context['passwordform'] = password_form
    return render(request, 'accounts/change-password.html', context)


#users views
@super_admin_required
@login_required(login_url='super_admin_login')
def users(request):
    context = {}
    context['active_sidebar'] = 'users'
    try:
        user = SharedUsers.objects.get(user=request.user)
        if user:
            context['disable_add_user'] = True
    except Exception as e:
        print(e)

    users = SharedUsers.objects.filter(belongs_to=request.user).order_by('-id')
    paginator = Paginator(users, 20)  
    page = request.GET.get('page')
    
    try:
        users = paginator.page(page)
    except PageNotAnInteger:
        users = paginator.page(1)
    except EmptyPage:
        users = paginator.page(paginator.num_pages)
        
    context['users'] = users
    return render(request, 'users/users.html',context)


@super_admin_required
@login_required(login_url='super_admin_login')
def add_user(request):
    context = {}
    context['active_sidebar'] = 'users'
    
    if request.method == 'POST':
        user_form = CustomUserCreationForm(request.POST, request.FILES)
        if user_form.is_valid():
            email = user_form.cleaned_data.get('email')
            password = user_form.cleaned_data.get('password1')
            form_instance = user_form.save(commit=False)
            form_instance.role = User.Roles.ADMIN
            form_instance.is_staff = True
            form_instance.is_superuser = True
            form_instance.save()
            user = SharedUsers.objects.create(user=form_instance, belongs_to=request.user)
            url = f'{settings.FRONTEND_URL}/login/'
            response = send_account_credentials_email(email, password, url)
            if response:
                messages.success(request, 'New user successfully added.')
            else:
                messages.success(request, 'New user successfully added, but email not found.')
            return redirect('users')
        else:
            context['form'] = user_form
    else:
        user_form = CustomUserCreationForm()
        context['form'] = user_form

    return render(request, 'users/add-user.html', context)


@super_admin_required
@login_required(login_url='super_admin_login')
def suspend_user(request, pk):
    context = {}
    context['active_sidebar'] = 'users'
    user = User.objects.get(id = pk)
    if user is not None:
        user.is_active = False
        user.save()
        messages.success(request, 'User account successfully suspended.')
    else:
        messages.error(request, 'User not found.')
    return redirect('users')


@super_admin_required
@login_required(login_url='super_admin_login')
def activate_user(request, pk):
    context = {}
    context['active_sidebar'] = 'users'
    user = User.objects.get(id = pk)
    if user is not None:
        user.is_active = True
        user.save()
        messages.success(request, 'User account successfully re-activated.')
    else:
        messages.error(request, 'User not found.')
    return redirect('users')


@super_admin_required
@login_required(login_url='super_admin_login')
def delete_user(request, pk):
    context = {}
    context['active_sidebar'] = 'users'
    user = User.objects.get(id = pk)
    if user is not None:
        user.delete()
        messages.success(request, 'User successfully deleted.')
    else:
        messages.error(request, 'User not found.')
    return redirect('users')


replacements = {
    'Ã‰': 'É', 'Ã¨': 'è', 'Ã©': 'é', 'Ã ': 'à', 'Ãª': 'ê', 'Ã®': 'î', 'Ã´': 'ô',
    'Ã¹': 'ù', 'Ã§': 'ç', 'Ã«': 'ë', 'Ã¯': 'ï', 'Ã¼': 'ü', 'Ãƒ': 'Ã', 'ãƒ': 'Ã',
    'â€™': "'", 'â€"': '-', 'â€œ': '"', 'â€': '"', 'â€¢': '•', 'â€¦': '…',
    'Ã¡': 'á', 'Ã¢': 'â', 'Ã£': 'ã', 'Ã¤': 'ä', 'Ã¥': 'å', 'Ã¦': 'æ',
    'Ã¬': 'ì', 'Ã±': 'ñ', 'Ã²': 'ò', 'Ã³': 'ó', 'Ã¶': 'ö', 'Ã¸': 'ø',
    'Ã½': 'ý', 'Ã¿': 'ÿ', 'Å': 'Š', 'å': 'Š', 'Å¡': 'š', 'Å¸': 'Ÿ', 'Å½': 'Ž', 'Å¾': 'ž',
    'Å‚': 'ł', 'Å„': 'ń', 'Å¡': 'š', 'Å¸': 'Ÿ', 'Å¾': 'ž', 'ã«': 'ë', 'ã©': 'é'
}

def replace_chars_in_file(file, column_map):
    # Determine the file extension
    file_extension = os.path.splitext(file.name)[1].lower()
    
    if file_extension == '.xlsx':
        # Load the Excel file
        df = pd.read_excel(file, sheet_name=None, dtype=str)
        
        # Convert column names to lowercase
        for sheet_name in df.keys():
            df[sheet_name].columns = df[sheet_name].columns.str.lower()
        
        # Iterate over each sheet
        for sheet_name, sheet_df in df.items():
            # Iterate over each column
            for column in sheet_df.columns:
                # Apply replacements if the column is of type string
                if sheet_df[column].dtype == 'object':
                    for old_char, new_char in replacements.items():
                        sheet_df[column] = sheet_df[column].str.replace(old_char, new_char, regex=False)
                if column in ['landline', 'cell_phone']:
                    sheet_df[column] = sheet_df[column].fillna('').astype(str)
        
        return df, {"success": True}
        
    elif file_extension == '.csv':
        # Load the CSV file
        df = pd.read_csv(file, dtype=str, usecols=lambda col: col.lower() in column_map)
        
        # Convert column names to lowercase
        df.columns = df.columns.str.lower()
        
        # Iterate over each column
        for column in df.columns:
            # Apply replacements if the column is of type string
            if df[column].dtype == 'object':
                for old_char, new_char in replacements.items():
                    df[column] = df[column].str.replace(old_char, new_char, regex=False)
            if column in ['landline', 'cell_phone']:
                df[column] = df[column].fillna('').astype(str)
        
        return df, {"success": True}

    else:
        return None, {"success": False, "error": "Unsupported file format. Please provide an Excel (.xlsx) or CSV (.csv) file."}


@csrf_exempt
def import_file_data(request):
    if request.method == 'POST':
        try:
            if 'data_file' in request.FILES:
                file = request.FILES['data_file']
                file_extension = os.path.splitext(file.name)[1].lower()
                if file_extension not in ['.xlsx', '.xls', '.csv']:
                    return JsonResponse({'success': False, 'message': 'Invalid file format'}, status=400)

                column_map = {
                    'full_name': 'full_name',
                    'first_name': 'first_name',
                    'last_name': 'last_name',
                    'headline': 'headline',
                    'current_position': 'current_position',
                    'company_name': 'company_name',
                    'person_city': 'person_city',
                    'person_state': 'person_state',
                    'person_country': 'person_country',
                    'person_industry': 'person_industry',
                    'tags': 'tags',
                    'person_skills': 'person_skills',
                    'education_experience': 'education_experience',
                    'company_website': 'company_website',
                    'email_perso': 'email1',
                    'email_pro': 'email2',
                    'landline': 'phone1',
                    'cell_phone': 'phone2',
                    'person_linkedin_url': 'person_linkedin_url',
                    'company_size_from': 'company_size_from',
                    'company_size_to': 'company_size_to',
                    'current_position_2': 'current_position_2',
                    'current_company_2': 'current_company_2',
                    'previous_position_2': 'previous_position_2',
                    'previous_company_2': 'previous_company_2',
                    'previous_position_3': 'previous_position_3',
                    'previous_company_3': 'previous_company_3',
                    'company_city': 'company_city',
                    'company_state': 'company_state',
                    'company_country': 'company_country',
                    'person_angellist_url': 'person_angellist_url',
                    'person_crunchbase_url': 'person_crunchbase_url',
                    'person_twitter_url': 'person_twitter_url',
                    'person_facebook_url': 'person_facebook_url',
                    'company_linkedin_url': 'company_linkedin_url',
                    'person_image_url': 'person_image_url',
                    'company_logo_url': 'company_logo_url',
                }

                # Convert the column map to use lowercase keys
                column_map_lower = {key.lower(): value for key, value in column_map.items()}
                
                cleaned_data, status = replace_chars_in_file(file, column_map_lower)
                if not status['success']:
                    return JsonResponse(status, status=400)
                
                if file_extension in ['.xlsx', '.xls']:
                    df = pd.concat(cleaned_data.values(), ignore_index=True)
                else:
                    df = cleaned_data

                df.fillna('', inplace=True)

                # Get the list of valid columns based on the column_map
                valid_columns = list(column_map_lower.keys())

                # Filter the DataFrame to include only valid columns
                df = df[[col for col in df.columns if col.lower() in valid_columns]]

                new_instances = []
                duplicate_instances = []
                is_duplicate = False

                linkedin_urls = set(df['person_linkedin_url'].dropna().unique())
                email1_list = set(df['email_perso'].dropna().unique())
                email2_list = set(df['email_pro'].dropna().unique())
                full_names = set(df['full_name'].dropna().unique())

                potential_duplicates = CandidateProfiles.objects.filter(
                    Q(full_name__in=full_names) |
                    Q(person_linkedin_url__in=linkedin_urls) |
                    Q(email1__in=email1_list) |
                    Q(email2__in=email1_list) |
                    Q(email1__in=email2_list) |
                    Q(email2__in=email2_list)
                )

                lookup = {
                    'full_name': {profile.full_name: profile for profile in potential_duplicates},
                    'linkedin': {profile.person_linkedin_url: profile for profile in potential_duplicates},
                    'email1': {profile.email1: profile for profile in potential_duplicates},
                    'email2': {profile.email2: profile for profile in potential_duplicates}
                }

                df = process_dataframe(df, column_map_lower, lookup)
                new_instances, duplicate_instances = separate_instances(df)

                # for index, row in df.iterrows():
                #     profile_data = {}
                #     for column_name_in_df, field_name_in_model in column_map_lower.items():
                #         value = row.get(column_name_in_df, None)
                #         if field_name_in_model == 'person_skills' and value:
                #             value = value.split(',')
                #         if (field_name_in_model == 'company_size_from' or field_name_in_model == 'company_size_to') and value:
                #             value = int(float(value))
                #         if value == '':
                #             value = None
                #         profile_data[field_name_in_model] = value
                    
                #     email = profile_data['email1']
                #     email2 = profile_data['email2']
                #     linkedin_url = profile_data['person_linkedin_url']
                #     try:
                #         original_profile = CandidateProfiles.objects.filter(person_linkedin_url=linkedin_url).first()
                #         if email is not None:
                #             if not original_profile:
                #                 original_profile = CandidateProfiles.objects.filter(Q(email1=email) | Q(email2=email), email1__isnull=False).first()
                #             if not original_profile:
                #                 original_profile = CandidateProfiles.objects.filter(Q(email1=email) | Q(email2=email), email2__isnull=False).first()
                #         if email2 is not None:    
                #             if not original_profile:
                #                 original_profile = CandidateProfiles.objects.filter(Q(email1=email2) | Q(email2=email2), email1__isnull=False).first()
                #             if not original_profile:
                #                 original_profile = CandidateProfiles.objects.filter(Q(email1=email2) | Q(email2=email2), email2__isnull=False).first()
                #         if original_profile:
                #             profile_data['original_profile'] = original_profile
                #             duplicate_instances.append(profile_data)
                #             is_duplicate = True
                #         else:
                #             new_instances.append(CandidateProfiles(**profile_data))
                #     except CandidateProfiles.DoesNotExist:
                #         new_instances.append(CandidateProfiles(**profile_data))
                
                # CandidateProfiles.objects.bulk_create(new_instances)
                parallel_bulk_insert(new_instances, chunk_size=1000, max_workers=4)
                
                DuplicateProfiles.objects.all().delete()
                parallel_duplicate_bulk_insert(duplicate_instances, chunk_size=1000, max_workers=4)
                # for duplicate_data in duplicate_instances:
                #     DuplicateProfiles.objects.update_or_create(email1=duplicate_data['email1'], defaults=duplicate_data)
                if len(duplicate_instances) > 0:
                    is_duplicate = True    
                return JsonResponse({'success': True, 'message': 'Data uploaded', 'is_duplicate': is_duplicate}, status=200)
            return JsonResponse({'success': False, 'message': 'File not found'}, status=400)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'File Import Failed: Please check your file carefully. The column titles may not match the required standards, or some data may be missing. Verify that all required headings are present, in the correct order, and match the standard format before attempting to upload again.'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


def export_file_data(request):
    fields = [field.name for field in CandidateProfiles._meta.fields]

    if 'id' in fields:
        fields.remove('id')

    # Initialize DataFrame with empty data
    # df = pd.DataFrame(columns=fields)
    # if not df.empty:
    #     queryset = CandidateProfiles.objects.all().values(*fields)
    #     df = pd.DataFrame(queryset)

    replacements = {
        'email1': 'Email_perso',
        'email2': 'Email_pro',
        'phone1': 'Landline',
        'phone2': 'Cell_phone'
    }
    
    queryset = CandidateProfiles.objects.all().values(*fields)
    df = pd.DataFrame(list(queryset))
    df = df.rename(columns=replacements, inplace=False)
    
    # Convert person_skills from list to comma-separated string
    if 'person_skills' in df.columns:
        df['person_skills'] = df['person_skills'].apply(lambda x: ','.join(x) if isinstance(x, list) else x)

     # data = df.to_dict(orient='records')
    # return JsonResponse(data, safe=False)
    
    # Remove indexes
    df = df.reset_index(drop=True)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="data.csv"'
    df.to_csv(response, index=False)
    return response


@csrf_exempt
def get_candidate_data(request, params):
    context = {}
    context['msg'] = None
    context['success'] = False
    model = CandidateProfiles
    field_names = [field.name for field in model._meta.get_fields()]
    formatted_field_names = [field.replace('_', ' ').capitalize() for field in field_names]
    formatted_field_names = formatted_field_names[2:]

    replacements = {
        'Email1': 'Email Perso',
        'Email2': 'Email Pro',
        'Phone1': 'Landline',
        'Phone2': 'Cell Phone'
    }
    formatted_field_names = [
        replacements.get(field, field) for field in formatted_field_names
    ]

    context['field_names'] =  formatted_field_names
    try:
        params_list = params.split('&')
        params_dict = {}
        for param in params_list:
            key, value = param.split('=')
            params_dict[key] = value
        page_number = params_dict.get("page", None)
        search_params = params_dict.get("q", '')

        fields_to_search = ['full_name', 'company_name', 'current_position', 'email1', 'phone1', 'person_city', 'person_skills']
        q_objects = [Q(**{f"{field}__icontains": search_params}) for field in fields_to_search]
        combined_filter = reduce(operator.or_, q_objects)

        users = CandidateProfiles.objects.filter(combined_filter).order_by('-id')
        paginator = Paginator(users, 20)
        page_obj = paginator.get_page(page_number)
        context['current_page'] = page_obj.number
        context['total_pages'] = paginator.num_pages
        context['has_next'] = page_obj.has_next()
        context['has_previous'] = page_obj.has_previous()
        text_template = loader.get_template('ajax/candidate-table.html')
        html = text_template.render({'page_obj':page_obj, 'field_names': context['field_names'], 'search_params': search_params, 'current_page': context['current_page'], 'total_pages': context['total_pages']})
        context['html'] = html
        context['user_count'] = paginator.count
        context['msg'] = 'Successfully retrieved registered users'
        context['success'] = True
    except Exception as e:
        print(e)
    return JsonResponse(context)


@csrf_exempt
def get_duplicate_data(request, params):
    context = {}
    context['msg'] = None
    context['success'] = False
    model = CandidateProfiles
    field_names = [field.name for field in model._meta.get_fields()]
    formatted_field_names = [field.replace('_', ' ').capitalize() for field in field_names]
    formatted_field_names = formatted_field_names[2:]

    replacements = {
        'Email1': 'Email Perso',
        'Email2': 'Email Pro',
        'Phone1': 'Landline',
        'Phone2': 'Cell Phone'
    }
    formatted_field_names = [
        replacements.get(field, field) for field in formatted_field_names
    ]

    context['field_names'] =  formatted_field_names
    try:
        params_list = params.split('&')
        params_dict = {}
        for param in params_list:
            key, value = param.split('=')
            params_dict[key] = value
        page_number = params_dict.get("page", None)
        search_params = params_dict.get("q", '')

        fields_to_search = ['full_name', 'company_name', 'current_position', 'email1', 'phone1', 'person_city', 'person_skills', 'original_profile__full_name', 'original_profile__company_name', 'original_profile__current_position', 'original_profile__email1', 'original_profile__phone1', 'original_profile__person_city', 'original_profile__person_skills']
        q_objects = [Q(**{f"{field}__icontains": search_params}) for field in fields_to_search]
        combined_filter = reduce(operator.or_, q_objects)

        users = DuplicateProfiles.objects.filter(combined_filter).order_by('-id')
        paginator = Paginator(users, 20)
        page_obj = paginator.get_page(page_number)
        context['current_page'] = page_obj.number
        context['total_pages'] = paginator.num_pages
        context['has_next'] = page_obj.has_next()
        context['has_previous'] = page_obj.has_previous()
        text_template = loader.get_template('ajax/manage-conflict-table.html')
        html = text_template.render({'page_obj':page_obj, 'field_names': context['field_names'], 'search_params': search_params, 'current_page': context['current_page'], 'total_pages': context['total_pages']})
        context['html'] = html
        context['msg'] = 'Successfully retrieved duplicate users'
        context['success'] = True
    except Exception as e:
        print(e)
    return JsonResponse(context)


@csrf_exempt
def resolve_conflict(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            to_preserve = data.get('toPreserve')
            to_delete = data.get('toDelete')
            type_of_record = data.get('type')
            
            if type_of_record == 'original':
                DuplicateProfiles.objects.filter(id=to_delete).delete()
            elif type_of_record == 'duplicate':
                duplicate_profile = DuplicateProfiles.objects.get(id=to_preserve)
                profile_data = {field.name: getattr(duplicate_profile, field.name) for field in DuplicateProfiles._meta.fields if field.name != 'original_profile' and field.name != 'id'}
                CandidateProfiles.objects.filter(id=to_delete).delete()
                CandidateProfiles.objects.create(**profile_data)
            # return JsonResponse({'success': False, 'message': 'New Password and Confirm Password do not match'}, status=400)
            return JsonResponse({'success': True, 'message': 'Conflict resolved successfully'}, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@super_admin_required
def keep_recent_records(request):
    if request.method == "POST":
        duplicate_profiles = DuplicateProfiles.objects.all().order_by('-id')
        for duplicate in duplicate_profiles:
            try:
                duplicate.resolve_conflict()
            except Exception as e:
                print(e)
        return JsonResponse({'success': True, 'message': 'Conflicts resolved successfully'}, status=200)
        # try:
        #     duplicate_profiles = DuplicateProfiles.objects.all().order_by('-id')
        #     for duplicate in duplicate_profiles:
        #         # duplicate.keep_most_recent()         
        #         duplicate.resolve_conflict()
        #     return JsonResponse({'success': True, 'message': 'Conflicts resolved successfully'}, status=200)
        # except Exception as e:
        #     print(e)
        # return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


def update_country(records, location):
    normalized_location_string = []
    hyphenated_location_string = []
    location = [loc.lower() for loc in location]
    for loc in location:
        normalized_location_string.append(loc.replace('-', ' '))
        hyphenated_location_string.append(loc.replace(' ', '-'))
    for record in records:
        if not record['person_country']:
            match_query = Q()
            match_query |= (Q(city_code__iexact=record['person_city']) | Q(city_code__iexact=record['person_state']) | Q(label__iexact=record['person_city']) | Q(label__iexact=record['person_state']))
            matching_location = LocationDetails.objects.filter(match_query).first()
            if matching_location:
                record['person_country'] = matching_location.region_name.title()
            else:
                record['person_country'] = record['person_state']
    return records


def build_whole_word_regex(keywords):
    if isinstance(keywords, str):
        keywords = [keywords]
    if not keywords:
        return None
    # keywords_pattern = '|'.join(rf'(?<!\w){keyword}(?!\w)' for keyword in keywords)
    keywords_pattern = '|'.join(rf'(?<!\w)(?<![a-zA-Z0-9_]){re.escape(keyword)}(?![a-zA-Z0-9_])(?!\w)' for keyword in keywords)
    return rf'(?i)({keywords_pattern})'


def build_regex_pattern(keyword):
    # return rf'(?i)(?<!\w){re.escape(keyword)}(?!\w)'
    escaped_keyword = re.escape(keyword)
    return rf'(?i)(?<!\w)(?<![a-zA-Z0-9_]){escaped_keyword}(?![a-zA-Z0-9_])(?!\w)'


def build_advanced_keyword_query(keywords, fields, array_fields=None):
    phrases, terms = parse_search_query(keywords)
    query = Q()
    current_query = Q()
    operator = 'AND'
    negate_next = False

    for term in terms:
        if term.upper() == 'AND':
            operator = 'AND'
        elif term.upper() == 'OR':
            operator = 'OR'
        elif term.upper() == 'NOT':
            negate_next = True
        else:
            term_query = Q()
            regex_pattern = build_regex_pattern(term)
            for field in fields:
                term_query |= Q(**{f'{field}__regex': regex_pattern})
            
            if negate_next:
                term_query = ~term_query
                negate_next = False
            
            if operator == 'AND':
                current_query &= term_query
            else:  # OR
                query |= current_query
                current_query = term_query

    query |= current_query  # Add the last term

    if array_fields:
        array_query = Q()
        for array_field in array_fields:
            array_query |= Q(**{f'{array_field}__regex': query})
        query |= array_query
    # print(query)
    return query


def build_simple_keyword_query(keywords, fields, array_fields=None):
    regex_pattern = build_whole_word_regex(keywords)
    if not regex_pattern:
        return Q()
    
    query = Q()
    for field in fields:
        query |= Q(**{f'{field}__regex': regex_pattern})
    
    if array_fields:
        for array_field in array_fields:
            # Annotate the queryset with a subquery to filter the array field elements
            subquery = Subquery(
                CandidateProfiles.objects.filter(
                        pk=OuterRef('pk'),
                        **{f'{array_field}__regex': regex_pattern}
                    )
                    .values_list('pk', flat=True)[:1]
            )
            query |= Q(pk__in=subquery)

    return query


def build_keyword_query(keywords, fields, array_fields=None, use_advanced=False):
    if use_advanced:
        return build_advanced_keyword_query(keywords, fields, array_fields)
    else:
        return build_simple_keyword_query(keywords, fields, array_fields)


keyword_fields = [
    'full_name', 'first_name', 'last_name', 'headline', 'current_position', 
    'company_name', 'person_industry', 'tags', 'person_skills', 'education_experience',
    'previous_position_2', 'previous_position_3'
]


search_fields = [
    'id', 'full_name', 'first_name', 'last_name', 'headline', 'current_position',
    'company_name', 'person_city', 'person_state', 'person_country', 'person_industry',
    'tags', 'person_skills', 'education_experience', 'company_website', 'email1',
    'email2', 'phone1', 'phone2', 'person_linkedin_url', 'company_size_from',
    'company_size_to', 'current_position_2', 'current_company_2', 'previous_position_2',
    'previous_company_2', 'previous_position_3', 'previous_company_3', 'company_city',
    'company_state', 'company_country', 'person_angellist_url', 'person_crunchbase_url',
    'person_twitter_url', 'person_facebook_url', 'company_linkedin_url', 'person_image_url', 'company_logo_url'
]


class ArrayLength(Func):
    function = 'array_length'
    template = '%(function)s(%(expressions)s, 1)'
    output_field = IntegerField()


@csrf_exempt
def search_profile(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user = query_dict.get('user_id', None)
            keywords = query_dict.get('keywords', '').lower()
            location = query_dict.get('location', [])
            job_titles = query_dict.get('jobs_title_list', [])
            skills = query_dict.get('skills_list', [])
            company_names = query_dict.get('company_name_list', [])
            company_size_ranges = query_dict.get('company_size_ranges', [])
            contact_details = query_dict.get('contact_details', [])
            company_size_from = query_dict.get('size_from', None)
            company_size_to = query_dict.get('size_to', None)
            contact_name = query_dict.get('contact_name', '')
            job_skill_list = job_titles + skills
            
            use_advanced_search = is_advanced_search(keywords)
            if use_advanced_search:
                is_valid, error_message = validate_query(keywords)
                if not is_valid:
                    context['success'] = False
                    context['message'] = error_message
                    return JsonResponse(context, status=400)

            if company_size_from in ["", "null"]:
                company_size_from = None
            if company_size_to in ["", "null"]:
                company_size_to = None

            records = CandidateProfiles.objects.all().order_by('-id')
            records = records.annotate(
                lower_company_name=Lower('company_name'),
                personCity=Lower('person_city'),
                personState=Lower('person_state'),
                personCountry=Lower('person_country')
            )

            is_france = any(loc.lower() == 'france' for loc in location)
            if len(location) > 0 and is_france == False:
                location = [loc.lower() for loc in location]
                normalized_location_string = [loc.replace('-', ' ') for loc in location]
                hyphenated_location_string = [loc.replace(' ', '-') for loc in location]
                
                location_variants = location + normalized_location_string + hyphenated_location_string
                location_variants = list(set(location_variants))
                
                match_query = Q()
                for loc in location_variants:
                    match_query |= (Q(region_name__iexact=loc) | Q(department_name__iexact=loc))
                matching_locations = LocationDetails.objects.filter(match_query).distinct()
                city_labels = list(matching_locations.values_list('label', flat=True))

                city_labels = [loc.lower() for loc in city_labels]
                normalized_city_labels = [loc.replace('-', ' ') for loc in city_labels]
                hyphenated_city_labels = [loc.replace(' ', '-') for loc in city_labels]
                
                city_label_variants = city_labels + normalized_city_labels + hyphenated_city_labels
                city_label_variants = list(set(city_label_variants))

                location_query = Q(
                    personCity__in=location_variants + city_label_variants
                ) | Q(
                    personState__in=location_variants + city_label_variants
                ) | Q(
                    personCountry__in=location_variants + city_label_variants
                )
                records = records.filter(location_query)

            # Apply company name filter
            if len(company_names) > 0:
                company_name_query = Q()
                for term in company_names:
                    company_name_query |= Q(company_name__icontains=term)
                records = records.filter(company_name_query)
            
            # Apply company size filter
            if len(company_size_ranges) > 0:
                company_size_query = Q()
                for size_range in company_size_ranges:
                    size_from = size_range.get('from')
                    size_to = size_range.get('to')
                    try:
                        size_from = int(size_from)
                    except (ValueError, TypeError):
                        continue
                    try:
                        size_to = int(size_to)
                    except (ValueError, TypeError):
                        size_to = None
                    if size_to is None:
                        company_size_query |= Q(company_size_from__gte=size_from)
                    else:
                        company_size_query |= Q(company_size_from__gte=size_from, company_size_to__lte=size_to)
                        # company_size_query |= Q(company_size_from__range=(size_from, size_to))
                valid_data_query = Q(company_size_to__isnull=True) | Q(company_size_from__lte=F('company_size_to'))
                records = records.filter(company_size_query & valid_data_query)

            # Apply contact details filter
            if len(contact_details) > 0:
                query = Q()
                field_mapping = {'email1': 'email1', 'email2': 'email2', 'phone1': 'phone1', 'phone2': 'phone2'}
                operation = query_dict.get('contact_details_radio', 'or')
                for field in contact_details:
                    if field in field_mapping:
                        q = Q(**{f"{field_mapping[field]}__isnull": False}) & ~Q(**{f"{field_mapping[field]}": ''})
                        if operation == 'or':
                            query |= q
                        elif operation == 'and':
                            query &= q
                records = records.filter(query)

            # Apply contact name filter
            records = records.filter(Q(full_name__icontains=contact_name) | Q(first_name__icontains=contact_name) | Q(last_name__icontains=contact_name))

            # keyword_query = build_keyword_query(keywords, keyword_fields, use_advanced=use_advanced_search)
            if use_advanced_search:
                keyword_query = boolean_search(keywords, keyword_fields)
            else:
                keyword_query = build_keyword_query(keywords, keyword_fields)
            
            # Create the query for skills
            combined_keyword_query = Q()
            if len(job_skill_list) > 0:
                combined_keyword_queries = [
                    Q(full_name__icontains=job_skill) | Q(first_name__icontains=job_skill) |
                    Q(last_name__icontains=job_skill) | Q(headline__icontains=job_skill) |
                    Q(current_position__icontains=job_skill) | Q(company_name__icontains=job_skill) |
                    Q(person_industry__icontains=job_skill)
                    # Q(person_skills__icontains=job_skill)
                    for job_skill in job_skill_list
                ]
                combined_keyword_query = combined_keyword_queries.pop()
                for q in combined_keyword_queries:
                    combined_keyword_query |= q
            
            # For priority 4
            if use_advanced_search:
                key_q = boolean_search(keywords, ['headline', 'current_position'])
            else:
                key_q = build_keyword_query(keywords, ['headline', 'current_position'])
            j_queries = build_keyword_query(job_titles, ['headline', 'current_position'])
            s_queries = build_keyword_query(skills, [], ['person_skills'])
            
            if keywords != '':
                priority_4 = records.filter(keyword_query).annotate(priority=Value(5, output_field=IntegerField()))
            elif len(job_titles) > 0:
                priority_4 = records.filter(j_queries).annotate(priority=Value(5, output_field=IntegerField()))
            elif len(skills) > 0:
                priority_4 = records.filter(s_queries).annotate(priority=Value(5, output_field=IntegerField()))
            else:
                priority_4 = records.annotate(priority=Value(999999, output_field=IntegerField()))

            ab = priority_4
            bool_search = priority_4

            if ((keywords != '' and len(job_titles) > 0) or (keywords != '' and len(skills) > 0) or (len(job_titles) > 0 and len(skills) > 0)) and use_advanced_search == False:
                ab = keyword_with_job_title_or_skill(priority_4, keywords, job_titles, skills)
            
            if use_advanced_search == True:
                bool_search = boolean_keyword_with_job_title_or_skill(priority_4, keywords, job_titles, skills)

            if keywords != '' and len(job_titles) == 0 and use_advanced_search == False and len(skills) == 0:
                keyword_lower = keywords.lower()
                exact_keyword = build_regex_pattern(keyword_lower)
                max_length = priority_4.aggregate(max_length=Max(ArrayLength(F('person_skills'))))['max_length'] or 0

                conditions = []
                for i in range(max_length):
                    conditions.append(
                        When(
                            **{f'person_skills__{i}__regex': exact_keyword},
                            then=Value(i + 1)
                        )
                    )

                priority_4 = priority_4.annotate(
                    skill_index=Case(
                        *conditions,
                        default=Value(999999),
                        output_field=IntegerField()
                    )
                ).annotate(priority=Value(2, output_field=IntegerField()))

                # For priority 1
                if keywords != '':
                    priority_4 = priority_4.annotate(
                        priority=Case(
                            When(key_q, then=Value(1)),
                            output_field=IntegerField(),
                        )
                    )            
            
            if keywords == '' and use_advanced_search == False and len(job_titles) > 0 and len(skills) == 0:
                job_title_queries = build_keyword_query(job_titles, ['headline', 'current_position'])
                priority_4 = priority_4.filter(job_title_queries)

                fields = ['headline', 'current_position']

                query = Q()
                for field in fields:
                    for job_title in job_titles:
                        regex = rf'(?i)(?<!\w){re.escape(job_title)}(?!\w)'
                        query |= Q(**{f'{field}__regex': regex})

                annotations = {
                    'match_count': Count(Case(
                        *[When(Q(**{f'{field}__regex': rf'(?i)(?<!\w){re.escape(job_title)}(?!\w)'}), then=1) 
                        for field in fields for job_title in job_titles],
                        output_field=IntegerField()
                    )),
                }

                for idx, job_title in enumerate(job_titles, start=1):
                    annotations[f'job_title_{idx}_count'] = Count(Case(
                        *[When(Q(**{f'{field}__regex': rf'(?i)(?<!\w){re.escape(job_title)}(?!\w)'}), then=1)
                        for field in fields],
                        output_field=IntegerField()
                    ))
                priority_4 = priority_4.annotate(**annotations)
            
            if keywords == '' and use_advanced_search == False and len(job_titles) == 0 and len(skills) > 0:
                max_length = priority_4.aggregate(max_length=Max(ArrayLength(F('person_skills'))))['max_length'] or 0
                priority_4 = search_skills(skills, priority_4)
            
            if keywords != '' and len(job_titles) == 0 and use_advanced_search == False and len(skills) == 0:
                combined_records = priority_4.order_by('priority', 'skill_index', '-id')
            elif keywords == '' and use_advanced_search == False and len(job_titles) > 0 and len(skills) == 0:
                order_by_fields = ['-match_count']
                for idx in range(1, len(job_titles) + 1):
                    order_by_fields.append(f'-job_title_{idx}_count')

                order_by_fields.append('-id')
                combined_records = priority_4.order_by(*order_by_fields)
            elif keywords == '' and use_advanced_search == False and len(job_titles) == 0 and len(skills) > 0:
                combined_records = priority_4
            elif ((keywords != '' and len(job_titles) > 0) or (keywords != '' and len(skills) > 0) or (len(job_titles) > 0 and len(skills) > 0)) and use_advanced_search == False:
                combined_records = ab
            elif use_advanced_search == True:
                combined_records = bool_search
            else:
                combined_records = priority_4.order_by('priority', '-id')

            # Pagination
            page_number = query_dict.get("page", 1)
            records_per_page = 20
            paginator = Paginator(combined_records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()


            actions = Actions.objects.filter(parent_user_id=user).order_by('-id')
            actions_mapping = {}
            for action in actions:
                if action.profile_id not in actions_mapping:
                    actions_mapping[action.profile_id] = []
                actions_mapping[action.profile_id].append({
                    'action_type': action.get_action_type_display(),
                    'action_type_value': action.action_type,
                    'parent_user': action.parent_user_id,
                    'action_user': action.action_user_id,
                    'comment': action.comment,
                    'action_datetime': action.action_datetime,
                    'id': action.id
                })

            # Prepare results
            page_obj = list(page_obj.object_list.values(*search_fields))
            for item in page_obj:
                item['show_email1'] = False
                item['show_email2'] = False
                item['show_phone1'] = False
                item['show_phone2'] = False
                item['is_favourite'] = False
                item['is_opened'] = False
                item['is_saved'] = CandidateProfiles.is_saved_for_user(item['id'], user)
                item['actions'] = actions_mapping.get(item['id'], [])
                try:
                    profile_visibility = ProfileVisibilityToggle.objects.get(search_user_id=user, candidate_id=item['id'])
                    item['show_email1'] = profile_visibility.show_email1
                    item['show_email2'] = profile_visibility.show_email2
                    item['show_phone1'] = profile_visibility.show_phone1
                    item['show_phone2'] = profile_visibility.show_phone2
                    item['is_favourite'] = profile_visibility.is_favourite
                    if item['show_email1'] or item['show_email2'] or item['show_phone1'] or item['show_phone2']:
                        item['is_opened'] = True
                except Exception as e:
                    print(e)
            # page_obj = update_country(page_obj_dicts, location)
            page_obj = update_country(page_obj, location)
            total_records = paginator.count

            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            # context['records'] = page_obj_dicts
            context['records'] = page_obj
            return JsonResponse(context, status=200)

        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@csrf_exempt
def search_profile_with_needs(request):
    if request.method != 'POST':
        return JsonResponse({"success": False, "message": "Invalid request method."}, status=405)

    try:
        context = {}
        query_dict = json.loads(request.body)
        user = query_dict.get('user_id')
        location = query_dict.get('locations', [])
        job_titles = query_dict.get('job_titles', [])
        skills = query_dict.get('skills', [])
        company_names = query_dict.get('company_names', [])
        company_size_ranges = query_dict.get('company_size_range', [])
        contact_details = query_dict.get('contact_details', '')
        min_score = query_dict.get('min_score', 0)

        # Define the filters for matching
        filters = {
            'job_title': job_titles,
            'technologies': skills,
        }

        # Prepare querysets and filters
        records = CandidateProfiles.objects.all().order_by('-id').annotate(
            lower_company_name=Lower('company_name'),
            personCity=Lower('person_city'),
            personState=Lower('person_state'),
            personCountry=Lower('person_country')
        )

        # Apply additional filters like location, company, etc.
        if location:
            records = filter_by_location(records, location)

        if company_names:
            records = records.filter(build_company_name_filter(company_names))

        if company_size_ranges:
            records = filter_by_company_size(records, company_size_ranges)

        if contact_details:
            records = filter_by_contact_details(records, contact_details)

        # # Filter by keywords, job titles, and skills
        # records = filter_by_keywords(records, keywords, job_titles, skills)

        j_queries = build_keyword_query(job_titles, ['headline', 'current_position'])
        s_queries = build_keyword_query(skills, [], ['person_skills'])
        
        if len(job_titles) > 0:
            records = records.filter(j_queries).annotate(priority=Value(5, output_field=IntegerField()))
        elif len(skills) > 0:
            records = records.filter(s_queries).annotate(priority=Value(5, output_field=IntegerField()))
        else:
            records = records.annotate(priority=Value(999999, output_field=IntegerField()))

        records = keyword_with_job_title_or_skill(records, '', job_titles, skills)


        # Step 4: Apply matching logic and filter profiles by match_score
        filtered_profiles = []
        for profile in records:
            match_score = calculate_match_score(profile, filters)
            if match_score >= min_score:  # Optionally, apply a minimum score filter
                profile_with_score = {
                    'profile': model_to_dict(profile),  # Convert profile to a dictionary
                    'match_score': match_score  # Include the match score
                }
                filtered_profiles.append(profile_with_score)

        # # Step 5: Sort profiles by match score in descending order
        # filtered_profiles.sort(key=lambda x: x['match_score'], reverse=True)

        # Step 6: Paginate the results
        page_number = query_dict.get("page", 1)
        records_per_page = 20
        paginator = Paginator(filtered_profiles, records_per_page)
        page_obj = paginator.get_page(page_number)
        context['current_page'] = page_obj.number
        context['total_pages'] = paginator.num_pages
        context['has_next'] = page_obj.has_next()
        context['has_previous'] = page_obj.has_previous()

        actions = Actions.objects.filter(parent_user_id=user).order_by('-id')
        actions_mapping = {}
        for action in actions:
            if action.profile_id not in actions_mapping:
                actions_mapping[action.profile_id] = []
            actions_mapping[action.profile_id].append({
                'action_type': action.get_action_type_display(),
                'action_type_value': action.action_type,
                'parent_user': action.parent_user_id,
                'action_user': action.action_user_id,
                'comment': action.comment,
                'action_datetime': action.action_datetime,
                'id': action.id
            })


        # Prepare results
        page_obj_list = []
        for item in page_obj.object_list:
            visibility_toggle = ProfileVisibilityToggle.objects.filter(candidate__id=item['profile']['id'], search_user_id=user).first()
            
            candidate_dict = {
                'id': item['profile']['id'],
                'full_name': item['profile']['full_name'],
                'first_name': item['profile']['first_name'],
                'last_name': item['profile']['last_name'],
                'headline': item['profile']['headline'],
                'current_position': item['profile']['current_position'],
                'company_name': item['profile']['company_name'],
                'person_city': item['profile']['person_city'],
                'person_state': item['profile']['person_state'],
                'person_country': item['profile']['person_country'],
                'person_industry': item['profile']['person_industry'],
                'tags': item['profile']['tags'],
                'person_skills': item['profile']['person_skills'],
                'education_experience': item['profile']['education_experience'],
                'company_website': item['profile']['company_website'],
                'email1': item['profile']['email1'],
                'email2': item['profile']['email2'],
                'phone1': item['profile']['phone1'],
                'phone2': item['profile']['phone2'],
                'person_linkedin_url': item['profile']['person_linkedin_url'],
                'company_size_from': item['profile']['company_size_from'],
                'company_size_to': item['profile']['company_size_to'],
                'current_position_2': item['profile']['current_position_2'],
                'current_company_2': item['profile']['current_company_2'],
                'previous_position_2': item['profile']['previous_position_2'],
                'previous_company_2': item['profile']['previous_company_2'],
                'previous_position_3': item['profile']['previous_position_3'],
                'previous_company_3': item['profile']['previous_company_3'],
                'company_city': item['profile']['company_city'],
                'company_state': item['profile']['company_state'],
                'company_country': item['profile']['company_country'],
                'person_angellist_url': item['profile']['person_angellist_url'],
                'person_crunchbase_url': item['profile']['person_crunchbase_url'],
                'person_twitter_url': item['profile']['person_twitter_url'],
                'person_facebook_url': item['profile']['person_facebook_url'],
                'company_linkedin_url': item['profile']['company_linkedin_url'],
                'person_image_url': item['profile']['person_image_url'],
                'company_logo_url': item['profile']['company_logo_url'],
                'match_score': item['match_score']
            }
            candidate_dict['actions'] = actions_mapping.get(item['profile']['id'], [])
            candidate_dict['show_email1'] = visibility_toggle.show_email1 if visibility_toggle else False
            candidate_dict['show_email2'] = visibility_toggle.show_email2 if visibility_toggle else False
            candidate_dict['show_phone1'] = visibility_toggle.show_phone1 if visibility_toggle else False
            candidate_dict['show_phone2'] = visibility_toggle.show_phone2 if visibility_toggle else False
            candidate_dict['is_favourite'] = visibility_toggle.is_favourite if visibility_toggle else False
            candidate_dict['is_saved'] = CandidateProfiles.is_saved_for_user(candidate_dict['id'], user)
            candidate_dict['is_opened'] = False
            if candidate_dict['show_email1'] or candidate_dict['show_email2'] or candidate_dict['show_phone1'] or candidate_dict['show_phone2']:
                    candidate_dict['is_opened'] = True
            page_obj_list.append(candidate_dict)

        page_obj = update_country(page_obj_list, location)
        total_records = paginator.count

        context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
        context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
        context['success'] = True
        context['records_count'] = total_records
        context['records'] = page_obj
        return JsonResponse(context, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "message": "Invalid JSON data."}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)}, status=500)
    

def filter_by_location(records, location):
    location = [loc.lower() for loc in location if loc.lower() != 'france']
    if not location:
        return records

    location_variants = generate_location_variants(location)
    matching_locations = LocationDetails.objects.filter(
        Q(region_name__in=location_variants) |
        Q(department_name__in=location_variants)
    ).distinct()

    city_labels = generate_location_variants([loc.lower() for loc in matching_locations.values_list('label', flat=True)])
    return records.filter(Q(personCity__in=location_variants + city_labels) |
                          Q(personState__in=location_variants + city_labels) |
                          Q(personCountry__in=location_variants + city_labels))


def build_company_name_filter(company_names):
    query = Q()
    for company in company_names:
        query |= Q(company_name__icontains=company)
    return query


def filter_by_company_size(records, company_size_ranges):
    if len(company_size_ranges) > 0:
        company_size_query = Q()
        for size_range in company_size_ranges:
            size_from = size_range.get('from')
            size_to = size_range.get('to')
            try:
                size_from = int(size_from)
            except (ValueError, TypeError):
                continue
            try:
                size_to = int(size_to)
            except (ValueError, TypeError):
                size_to = None
            if size_to is None:
                company_size_query |= Q(company_size_from__gte=size_from)
            else:
                company_size_query |= Q(company_size_from__range=(size_from, size_to))
        valid_data_query = Q(company_size_to__isnull=True) | Q(company_size_from__lte=F('company_size_to'))
        records = records.filter(company_size_query & valid_data_query)
    
    return records


def filter_by_contact_details(records, contact_keyword):
    # Define mappings for each type of contact detail
    field_mapping = {
        'email': ['email1', 'email2'],
        'phone': ['phone1', 'phone2'],
        'phone_or_email': ['email1', 'email2', 'phone1', 'phone2']
    }

    # Get the fields corresponding to the contact keyword
    fields = field_mapping.get(contact_keyword)
    if not fields:
        raise ValueError("Invalid contact keyword. Choose 'phone', 'email', or 'phone_email'.")

    # Build the query based on the contact keyword
    query = Q()
    for field in fields:
        condition = Q(**{f"{field}__isnull": False}) & ~Q(**{f"{field}": ''})
        query |= condition

    return records.filter(query)


def filter_by_keywords(records, keywords, job_titles, skills):
    if is_advanced_search(keywords):
        keyword_query = boolean_search(keywords)
    else:
        keyword_query = build_keyword_query(keywords, ['headline', 'current_position'])

    job_skill_list = job_titles + skills
    combined_keyword_query = Q()

    for job_skill in job_skill_list:
        combined_keyword_query |= Q(full_name__icontains=job_skill) | \
                                  Q(first_name__icontains=job_skill) | \
                                  Q(last_name__icontains=job_skill) | \
                                  Q(headline__icontains=job_skill) | \
                                  Q(current_position__icontains=job_skill)

    return records.filter(keyword_query | combined_keyword_query)


def generate_location_variants(locations):
    normalized = [loc.replace('-', ' ') for loc in locations]
    hyphenated = [loc.replace(' ', '-') for loc in locations]
    return list(set(locations + normalized + hyphenated))


def calculate_match_score(profile, filters):
    score = 0
    job_title_matches = 0
    skill_matches_in_job_title = 0
    skill_matches_in_top_skills = 0

    headline = profile.headline or ''
    current_position = profile.current_position or ''

    for keyword in filters['job_title']:
        job_title_pattern = build_regex_pattern(keyword)
        if re.search(job_title_pattern, headline) or re.search(job_title_pattern, current_position):
            job_title_matches += 1

    for skill in filters['technologies']:
        skill_pattern = build_regex_pattern(skill)
        if re.search(skill_pattern, headline) or re.search(skill_pattern, current_position):
            skill_matches_in_job_title += 1

    top_skills = profile.person_skills or []
    top_skills = top_skills[:3]
    for skill in filters['technologies']:
        top_skill_pattern = build_regex_pattern(skill)
        for top_skill in top_skills:
            if re.search(top_skill_pattern, top_skill):
                skill_matches_in_top_skills += 1
                break

    job_title_keywords = filters['job_title']
    technologies = filters['technologies']

    job_title_match_percentage = (job_title_matches / len(job_title_keywords)) * 100 if job_title_keywords else 0
    skill_match_percentage = (skill_matches_in_job_title / len(technologies)) * 100 if technologies else 0
    top_skill_match_percentage = (skill_matches_in_top_skills / len(technologies)) * 100 if technologies else 0

    avg_match_percentage = (job_title_match_percentage + skill_match_percentage + top_skill_match_percentage) / 3

    if job_title_matches >= 1 and skill_matches_in_job_title >= 2:
        base_score = 90
    elif job_title_matches >= 1 and skill_matches_in_job_title >= 1:
        base_score = 80
    elif job_title_matches >= 1 and skill_matches_in_top_skills >= 1:
        base_score = 60
    else:
        base_score = 50

    score = base_score + (avg_match_percentage / 10)
    return min(score, 100)


@csrf_exempt
def save_need_filters(request):
    if request.method == "POST":
        try:
            # Parse the JSON data from the request body
            data = json.loads(request.body)
            
            # Retrieve data from the request
            user = data.get('current_user_id')
            name = data.get('need')

            # For fields that expect a list, convert them into comma-separated strings
            job_title = ', '.join(data.get('job_titles', [])) if isinstance(data.get('job_titles'), list) else ''
            location = ', '.join(data.get('locations', [])) if isinstance(data.get('locations'), list) else ''
            skills = ', '.join(data.get('skills', [])) if isinstance(data.get('skills'), list) else ''
            companies = ', '.join(data.get('company_names', [])) if isinstance(data.get('company_names'), list) else '' 
            head_count = ', '.join(data.get('company_size_range', [])) if isinstance(data.get('company_size_range'), list) else ''
            start_date = data.get('start_date')
            end_date = data.get('end_date', None)
            percentage_filter = data.get('min_score', None)
            contact_type = data.get('contact_details', None)

            # Create a new Need instance and save it to the database
            need = Need.objects.create(
                user=user,
                name=name,
                job_title=job_title,
                location=location,
                skills=skills,
                current_company=companies,
                head_count=head_count,
                start_date=start_date,
                end_date=end_date,
                percentage_filter=percentage_filter,
                contact_type=contact_type
            )
            
            # Return a success response
            return JsonResponse({'success': True, 'message': 'Need filter saved successfully', 'need_id': need.id}, status=201)

        except (ValueError, KeyError, Exception) as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)

    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)
    

@csrf_exempt
def get_needs(request, pk):
    context = {}
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            page_number = data.get('page', 1)
            
            needs = Need.objects.filter(user=pk).order_by('-created_at')

            records_per_page = 20
            paginator = Paginator(needs, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = paginator.count
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            context['records'] = list(page_obj.object_list.values())
            return JsonResponse(context, status=200)
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)

    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)


@csrf_exempt
# @require_http_methods(["DELETE"])
def delete_need(request, pk, need_id):
    if request.method == "DELETE":
        print(pk, type(pk))
        print(need_id, type(need_id))
        try:
            try:
                need = Need.objects.get(user=pk, id=int(need_id))
            except Exception as e:
                need = None
            if need is None:
                return JsonResponse({'success': False, 'message': 'Need not found'}, status=404)
            need.delete()
            return JsonResponse({'success': True, 'message': 'Need deleted'}, status=204)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': f'Something bad happened {e}'}, status=500)
        
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=405)


class ArrayToString(Func):
    function = 'ARRAY_TO_STRING'
    template = "%(function)s(%(expressions)s, ' ')"


def search_skills(skills, queryset):
    max_length = queryset.aggregate(max_length=Max(ArrayLength(F('person_skills'))))['max_length'] or 0

    # Annotate with skills_string
    queryset = queryset.annotate(skills_string=ArrayToString('person_skills'))

    # Create a Case for each position and skill
    cases = []
    for position in range(max_length):
        for skill_index, skill in enumerate(skills):
            cases.append(
                When(
                    Q(skills_string__regex=build_regex_pattern(skill)) &
                    Q(person_skills__len__gt=position) &
                    Q(**{f'person_skills__{position}__regex': build_regex_pattern(skill)}),
                    then=Value(position * 1000 + skill_index)
                )
            )

    # Annotate with priority
    queryset = queryset.annotate(
        priority=Case(*cases, default=Value(1000000), output_field=IntegerField())
    )

    # Filter to include only profiles with at least one matching skill
    skill_filter = reduce(or_, [Q(skills_string__regex=build_regex_pattern(skill)) for skill in skills])
    queryset = queryset.filter(skill_filter)

    # Order by priority
    queryset = queryset.order_by('priority', '-id')

    return queryset


def create_skill_conditions(keywords, max_length):
    conditions = []
    max_length = max_length

    for keyword in keywords:
        exact_keyword = rf'(?i)(?<!\w)(?<![a-zA-Z0-9_]){re.escape(keyword)}(?![a-zA-Z0-9_])(?!\w)'

        for i in range(max_length):
            conditions.append(
                When(
                    **{f'person_skills__{i}__regex': exact_keyword},
                    then=Value((keywords.index(keyword) + 1) * 100 + (i + 1))
                )
            )
    
    return conditions


def is_advanced_search(keywords):
    # Check for presence of Boolean operators
    boolean_operators = r'\b(AND|OR|NOT)\b'
    if re.search(boolean_operators, keywords, re.IGNORECASE):
        return True
    
    # Check for presence of quotation marks (phrase search)
    if '"' in keywords:
        return True
    
    # Check for presence of parentheses (grouping)
    # if '(' in keywords or ')' in keywords:
    #     return True

    if re.search(r'\(\s*[^()]*\b(?:AND|OR|NOT)\b[^()]*\s*\)', keywords, re.IGNORECASE):
        return True
    
    # If none of the above conditions are met, it's a simple search
    return False


def parse_search_query(query):
    # Find phrases in quotation marks
    quoted_phrases = re.findall(r'"([^"]*)"', query)

    # Replace quoted phrases with placeholders
    placeholder = "QUOTED_PHRASE"
    for i, phrase in enumerate(quoted_phrases):
        query = query.replace(f'"{phrase}"', f'{placeholder}{i}', 1)
    
    # Find individual terms and operators
    terms = re.findall(r'\b(?:AND|OR|NOT|\(|\)|\S+)\b', query, re.IGNORECASE)
    
    # Replace placeholders with original quoted phrases
    terms = [term if not term.startswith(placeholder) else quoted_phrases[int(term[len(placeholder):])] for term in terms]
    
    # Treat individual words as phrases, excluding operators and parentheses
    phrases = [term for term in terms if term.upper() not in ['AND', 'OR', 'NOT'] and term not in ['(', ')']]
    
    return phrases, terms


def validate_query(query):
    # Remove extra spaces
    query = ' '.join(query.split())
    
    # Check for empty query
    if not query:
        return False, "Query cannot be empty."
    
    # Check for unmatched quotation marks
    if query.count('"') % 2 != 0:
        return False, "Quotations must be part of a complete expression and properly closed."
    
    # Check for unmatched parentheses
    if query.count('(') != query.count(')'):
        return False, "Parentheses must be part of a complete expression and properly closed."
    
    # Split the query into terms, preserving quoted phrases and parentheses
    terms = re.findall(r'[()]|"[^"]*"|\S+', query)
    
    # Check for misuse of Boolean operators
    operators = {'AND', 'OR', 'NOT'}
    for i, term in enumerate(terms):
        upper_term = term.upper()
        if upper_term in operators:
            if i == 0 or i == len(terms) - 1:
                return False, f"Misuse of {upper_term} operator at the beginning or end of the query."
            if terms[i-1].upper() in operators or terms[i+1].upper() in operators:
                return False, f"Misuse of {upper_term} operator: cannot be adjacent to another operator."
    
    # Check for proper use of parentheses
    paren_count = 0
    for term in terms:
        if term == '(':
            paren_count += 1
        elif term == ')':
            paren_count -= 1
        if paren_count < 0:
            return False, "Parentheses must be part of a complete expression and properly closed."
    
    # Check for empty groups
    if '()' in query:
        return False, "Unsupported syntax in query. Please revise your search terms."
    
    return True, ""


def tokenize(query):
    """
    Tokenizes the input query, handling quoted phrases and logical operators.
    """
    tokens = []
    i = 0
    length = len(query)
    while i < length:
        if query[i] in '()"':
            if query[i] == '"':
                end_quote = query.find('"', i + 1)
                if end_quote == -1:
                    end_quote = length
                tokens.append(query[i:end_quote + 1])
                i = end_quote + 1
            else:
                tokens.append(query[i])
                i += 1
        elif query[i].isspace():
            i += 1
        else:
            end = i
            while end < length and not query[end].isspace() and query[end] not in '()"':
                end += 1
            tokens.append(query[i:end])
            i = end
    return tokens

def boolean_search(query, fields):
    """
    Parse the boolean search query and construct a Q object for Django ORM.
    Accepts a list of fields to apply the query on.
    """
    # Tokenize the query
    tokens = tokenize(query)
    
    # Initialize an empty Q object
    q = Q()

    # Stack for grouping
    stack = []
    
    # Current operator context
    current_op = Q.__and__

    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token.upper() == 'AND':
            current_op = Q.__and__
        elif token.upper() == 'OR':
            current_op = Q.__or__
        elif token.upper() == 'NOT':
            next_token = tokens[i + 1]
            i += 1
            sub_q = Q()
            if next_token.startswith('"') and next_token.endswith('"'):
                exact_phrase = next_token.strip('"')
                for field in fields:
                    regex_pattern = build_regex_pattern(exact_phrase)
                    sub_q |= Q(**{f"{field}__regex": regex_pattern})
            else:
                for field in fields:
                    regex_pattern = build_regex_pattern(next_token)
                    sub_q |= Q(**{f"{field}__regex": regex_pattern})
            q &= ~sub_q
        elif token == '(':
            stack.append((q, current_op))
            q = Q()
            current_op = Q.__and__
        elif token == ')':
            if stack:
                prev_q, prev_op = stack.pop()
                q = prev_op(prev_q, q)
            current_op = Q.__and__
        elif token.startswith('"') and token.endswith('"'):
            exact_phrase = token.strip('"')
            sub_q = Q()
            for field in fields:
                regex_pattern = build_regex_pattern(exact_phrase)
                sub_q |= Q(**{f"{field}__regex": regex_pattern})
            q = current_op(q, sub_q)
        else:
            if token.upper() not in ['AND', 'OR', 'NOT']:
                sub_q = Q()
                for field in fields:
                    regex_pattern = build_regex_pattern(token)
                    sub_q |= Q(**{f"{field}__regex": regex_pattern})
                q = current_op(q, sub_q)
        
        i += 1

    return q


@csrf_exempt
def toggle_visibility(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get('user', None)
            record_id = data.get('record_id', None)            
            
            update_fields = {}
            fields = ['show_email1', 'show_email2', 'show_phone1', 'show_phone2', 'is_favourite']
            for field in fields:
                if field in data:
                    update_fields[field] = data[field]
            # update_fields = {'show_email1': show_email1, 'show_email2': show_email2, 'show_phone1': show_phone1, 'show_phone2': show_phone2}
            new = ProfileVisibilityToggle.objects.update_or_create(search_user_id=user_id, candidate_id=record_id, defaults=update_fields)
            return JsonResponse({'success': True, 'message': 'Visibility toggled successfully'}, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@csrf_exempt
def get_favourite_profiles(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')

            records = ProfileVisibilityToggle.objects.select_related('candidate').filter(search_user_id=int(user_id), is_favourite=True).order_by('-id')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')
            
            normalized_location_string = search_params.replace('-', ' ')
            hyphenated_location_string = search_params.replace(' ', '-')
            matching_locations = LocationDetails.objects.filter(
                Q(region_name__icontains=search_params) | Q(region_name__icontains=normalized_location_string) | 
                Q(region_name__icontains=hyphenated_location_string) | Q(department_name__icontains=search_params) |
                Q(department_name__icontains=normalized_location_string) | Q(department_name__icontains=hyphenated_location_string)
            )
            city_labels = matching_locations.values_list('label', flat=True)

            normalized_city_labels = []
            hyphenated_city_labels = []
            for label in city_labels:
                normalized_city_labels.append(label.replace('-', ' ').lower())
                hyphenated_city_labels.append(label.replace(' ', '-').lower())
            
            records = records.annotate(personCity=Lower('candidate__person_city'), personState=Lower('candidate__person_state'), personCountry=Lower('candidate__person_country'))

            records = records.filter(
                Q(candidate__full_name__icontains=search_params) | 
                Q(candidate__email1__icontains=search_params) | 
                Q(candidate__email2__icontains=search_params) | 
                Q(candidate__company_name__icontains=search_params) | 
                Q(candidate__headline__icontains=search_params) | 
                Q(candidate__current_position__icontains=search_params) | 
                Q(candidate__person_skills__icontains=search_params) |
                Q(personCity__icontains=search_params) |
                Q(personState__icontains=search_params) |
                Q(personCountry__icontains=search_params)
            )

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = paginator.count

            actions = Actions.objects.filter(parent_user_id=user_id).order_by('-id')
            actions_mapping = {}
            for action in actions:
                if action.profile_id not in actions_mapping:
                    actions_mapping[action.profile_id] = []
                actions_mapping[action.profile_id].append({
                    'action_type': action.get_action_type_display(),
                    'action_type_value': action.action_type,
                    'parent_user': action.parent_user_id,
                    'action_user': action.action_user_id,
                    'comment': action.comment,
                    'action_datetime': action.action_datetime,
                    'id': action.id
                })

            page_obj_list = []
            for item in page_obj.object_list:
                candidate_dict = {
                    'id': item.candidate.id,
                    'full_name': item.candidate.full_name,
                    'first_name': item.candidate.first_name,
                    'last_name': item.candidate.last_name,
                    'headline': item.candidate.headline,
                    'current_position': item.candidate.current_position,
                    'company_name': item.candidate.company_name,
                    'person_city': item.candidate.person_city,
                    'person_state': item.candidate.person_state,
                    'person_country': item.candidate.person_country,
                    'person_industry': item.candidate.person_industry,
                    'tags': item.candidate.tags,
                    'person_skills': item.candidate.person_skills,
                    'education_experience': item.candidate.education_experience,
                    'company_website': item.candidate.company_website,
                    'email1': item.candidate.email1,
                    'email2': item.candidate.email2,
                    'phone1': item.candidate.phone1,
                    'phone2': item.candidate.phone2,
                    'person_linkedin_url': item.candidate.person_linkedin_url,
                    'company_size_from': item.candidate.company_size_from,
                    'company_size_to': item.candidate.company_size_to,
                    'current_position_2': item.candidate.current_position_2,
                    'current_company_2': item.candidate.current_company_2,
                    'previous_position_2': item.candidate.previous_position_2,
                    'previous_company_2': item.candidate.previous_company_2,
                    'previous_position_3': item.candidate.previous_position_3,
                    'previous_company_3': item.candidate.previous_company_3,
                    'company_city': item.candidate.company_city,
                    'company_state': item.candidate.company_state,
                    'company_country': item.candidate.company_country,
                    'person_angellist_url': item.candidate.person_angellist_url,
                    'person_crunchbase_url': item.candidate.person_crunchbase_url,
                    'person_twitter_url': item.candidate.person_twitter_url,
                    'person_facebook_url': item.candidate.person_facebook_url,
                    'company_linkedin_url': item.candidate.company_linkedin_url,
                    'person_image_url': item.candidate.person_image_url,
                    'company_logo_url': item.candidate.company_logo_url
                }
                candidate_dict['actions'] = actions_mapping.get(item.candidate.id, [])
                candidate_dict['show_email1'] = item.show_email1
                candidate_dict['show_email2'] = item.show_email2
                candidate_dict['show_phone1'] = item.show_phone1
                candidate_dict['show_phone2'] = item.show_phone2
                candidate_dict['is_favourite'] = item.is_favourite
                candidate_dict['is_saved'] = CandidateProfiles.is_saved_for_user(candidate_dict['id'], user_id)
                candidate_dict['is_opened'] = False
                if candidate_dict['show_email1'] or candidate_dict['show_email2'] or candidate_dict['show_phone1'] or candidate_dict['show_phone2']:
                        candidate_dict['is_opened'] = True
                page_obj_list.append(candidate_dict)
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            context['records'] = page_obj_list
            return JsonResponse(context, status=200)
            

        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happed!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@csrf_exempt
def get_opened_profiles(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')

            query = Q(show_email1=True) | Q(show_email2=True) | Q(show_phone1=True) | Q(show_phone2=True)
            records = ProfileVisibilityToggle.objects.select_related('candidate').filter(query, search_user_id=int(user_id)).order_by('-id')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')
            
            records = records.annotate(personCity=Lower('candidate__person_city'), personState=Lower('candidate__person_state'), personCountry=Lower('candidate__person_country'))

            records = records.filter(
                Q(candidate__full_name__icontains=search_params) | 
                Q(candidate__email1__icontains=search_params) | 
                Q(candidate__email2__icontains=search_params) | 
                Q(candidate__company_name__icontains=search_params) | 
                Q(candidate__headline__icontains=search_params) | 
                Q(candidate__current_position__icontains=search_params) | 
                Q(candidate__person_skills__icontains=search_params) |
                Q(personCity__icontains=search_params) |
                Q(personState__icontains=search_params) |
                Q(personCountry__icontains=search_params)
            )

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = paginator.count

            actions = Actions.objects.filter(parent_user_id=user_id).order_by('-id')
            actions_mapping = {}
            for action in actions:
                if action.profile_id not in actions_mapping:
                    actions_mapping[action.profile_id] = []
                actions_mapping[action.profile_id].append({
                    'action_type': action.get_action_type_display(),
                    'action_type_value': action.action_type,
                    'parent_user': action.parent_user_id,
                    'action_user': action.action_user_id,
                    'comment': action.comment,
                    'action_datetime': action.action_datetime,
                    'id': action.id
                })

            page_obj_list = []
            for item in page_obj.object_list:
                candidate_dict = {
                    'id': item.candidate.id,
                    'full_name': item.candidate.full_name,
                    'first_name': item.candidate.first_name,
                    'last_name': item.candidate.last_name,
                    'headline': item.candidate.headline,
                    'current_position': item.candidate.current_position,
                    'company_name': item.candidate.company_name,
                    'person_city': item.candidate.person_city,
                    'person_state': item.candidate.person_state,
                    'person_country': item.candidate.person_country,
                    'person_industry': item.candidate.person_industry,
                    'tags': item.candidate.tags,
                    'person_skills': item.candidate.person_skills,
                    'education_experience': item.candidate.education_experience,
                    'company_website': item.candidate.company_website,
                    'email1': item.candidate.email1,
                    'email2': item.candidate.email2,
                    'phone1': item.candidate.phone1,
                    'phone2': item.candidate.phone2,
                    'person_linkedin_url': item.candidate.person_linkedin_url,
                    'company_size_from': item.candidate.company_size_from,
                    'company_size_to': item.candidate.company_size_to,
                    'current_position_2': item.candidate.current_position_2,
                    'current_company_2': item.candidate.current_company_2,
                    'previous_position_2': item.candidate.previous_position_2,
                    'previous_company_2': item.candidate.previous_company_2,
                    'previous_position_3': item.candidate.previous_position_3,
                    'previous_company_3': item.candidate.previous_company_3,
                    'company_city': item.candidate.company_city,
                    'company_state': item.candidate.company_state,
                    'company_country': item.candidate.company_country,
                    'person_angellist_url': item.candidate.person_angellist_url,
                    'person_crunchbase_url': item.candidate.person_crunchbase_url,
                    'person_twitter_url': item.candidate.person_twitter_url,
                    'person_facebook_url': item.candidate.person_facebook_url,
                    'company_linkedin_url': item.candidate.company_linkedin_url,
                    'person_image_url': item.candidate.person_image_url,
                    'company_logo_url': item.candidate.company_logo_url
                }
                candidate_dict['actions'] = actions_mapping.get(item.candidate.id, [])
                candidate_dict['show_email1'] = item.show_email1
                candidate_dict['show_email2'] = item.show_email2
                candidate_dict['show_phone1'] = item.show_phone1
                candidate_dict['show_phone2'] = item.show_phone2
                candidate_dict['is_favourite'] = item.is_favourite
                candidate_dict['is_saved'] = CandidateProfiles.is_saved_for_user(candidate_dict['id'], user_id)
                candidate_dict['is_opened'] = False
                if candidate_dict['show_email1'] or candidate_dict['show_email2'] or candidate_dict['show_phone1'] or candidate_dict['show_phone2']:
                        candidate_dict['is_opened'] = True
                page_obj_list.append(candidate_dict)
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            context['records'] = page_obj_list
            return JsonResponse(context, status=200)
            

        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happed!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@super_admin_required
def delete_specific_candidates(request, pk):
    if request.method == 'DELETE':
        try:
            try:
                candidate = CandidateProfiles.objects.get(id=int(pk))
            except Exception as e:
                candidate = None
            if candidate is None:
                return JsonResponse({'success': False, 'message': 'Profile not found'}, status=404)
            candidate.delete()
            return JsonResponse({'success': True, 'message': 'User deleted'}, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


# Temporary view to delete all candidates

# @super_admin_required
# def delete_all_candidates(request):
#     CandidateProfiles.objects.all().delete()
#     return redirect('/')


# Temporary view to delete all duplicates

@super_admin_required
def delete_all_duplicates(request):
    DuplicateProfiles.objects.all().delete()
    return redirect('/')


@csrf_exempt
def location_data_upload(request):
    if request.method == 'POST':
        try:
            file_obj = request.FILES['cities']
            data = json.load(file_obj)

            BATCH_SIZE = 100
            cities_data = data['cities']
            city_objects = []
            try:
                for i in range(0, len(cities_data), BATCH_SIZE):
                    city_batch = cities_data[i:i + BATCH_SIZE]
                    city_objects = [
                        LocationDetails(
                            insee_code=city_data['insee_code'],
                            city_code=city_data['city_code'],
                            zip_code=city_data['zip_code'],
                            label=city_data['label'],
                            latitude=city_data['latitude'],
                            longitude=city_data['longitude'],
                            department_name=city_data['department_name'],
                            department_number=city_data['department_number'],
                            region_name=city_data['region_name'],
                            region_geojson_name=city_data['region_geojson_name']
                        ) for city_data in city_batch
                    ]
                    LocationDetails.objects.bulk_create(city_objects)
            except KeyError as e:
                return JsonResponse({'error': f'{str(e)}'}, status=400)
                
            # LocationDetails.objects.bulk_create(city_objects)
                # LocationDetails.objects.create(
                #     insee_code=city_data['insee_code'],
                #     city_code=city_data['city_code'],
                #     zip_code=city_data['zip_code'],
                #     label=city_data['label'],
                #     latitude=city_data['latitude'],
                #     longitude=city_data['longitude'],
                #     department_name=city_data['department_name'],
                #     department_number=city_data['department_number'],
                #     region_name=city_data['region_name'],
                #     region_geojson_name=city_data['region_geojson_name']
                # )
            return JsonResponse({'status': 'success'}, status=201)
        except Exception as e:
            print(e)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def add_list(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            list_name = data.get('name', '')
            user_id = data.get('user_id', None)
            list_type = data.get('list_type', 'recruitment')
            if list_name == '':
                return JsonResponse({'success': False, 'message': 'List name is required'}, status=400)
            elif user_id == None:
                return JsonResponse({'success': False, 'message': 'User id is required'}, status=400)
            else:
                new_list = SavedLists.objects.create(list_user_id=user_id, name=list_name, list_type=list_type)
                new_list_json = serializers.serialize('json', [new_list])
                new_list_data = json.loads(new_list_json)[0]['fields']
                new_list_data['id'] = new_list.id
            return JsonResponse({'success': True, 'message': 'List created', 'data': new_list_data}, status=201)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@csrf_exempt
def delete_list(request):
    context = {}
    if request.method == "DELETE":
        try:
            data = json.loads(request.body)
            list_id = data.get('record_id', None)
            if list_id is not None:
                list_instance = SavedLists.objects.filter(id=list_id)
                if list_instance.exists():
                    list_instance.delete()
                    context['success'] = True
                    context['message'] = "List Deleted."
                else:
                    context['success'] = False
                    context['message'] = "Reocrd no found."
            else:
                context['success'] = False
                context['message'] = "record id can't be None"
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = e
    
    return JsonResponse(context)


@csrf_exempt
def update_list(request):
    context = {}
    if request.method == "PATCH":
        try:
            data = json.loads(request.body)
            print(data)
            list_id = data.get("list_id", None)
            list_name = data.get("name", '')
            list_type = data.get('list_type', '')
            
            print(list_id, list_name, list_type)
            
            if list_id is not None:
                old_instance = SavedLists.objects.get(id=list_id)
                if old_instance:
                    old_instance.name = list_name
                    old_instance.save(update_fields=['name'])
                    context['success'] = True
                    context['message'] = 'record updated.'
                else:
                    context['success'] = False
                    context['message'] = 'record not found.'
            else:
                context['success'] = False
                context['message'] = 'list id can not be none.'
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = e
    else:
        context['success'] = False
        context['message'] = "Invalid request"
    return JsonResponse(context)

@csrf_exempt
def get_recruitment_list(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')

            records = SavedLists.objects.filter(list_user_id=int(user_id), list_type=SavedLists.Types.RECRUITMENT).order_by('-id')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')

            records = records.filter(Q(name__icontains = search_params))
            records = records.annotate(profile_count=Count('savedlistprofiles'))

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = records.count()
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            context['records'] = list(page_obj.object_list.values())
            return JsonResponse(context, status=200)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@csrf_exempt
def get_prospection_list(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')

            records = SavedLists.objects.filter(list_user_id=int(user_id), list_type=SavedLists.Types.PROSPECTION).order_by('-id')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')

            records = records.filter(Q(name__icontains = search_params))
            records = records.annotate(profile_count=Count('savedlistprofiles'))

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = records.count()
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            context['records'] = list(page_obj.object_list.values())
            return JsonResponse(context, status=200)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@csrf_exempt
def add_record_in_list(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            record_id = data.get('record_id', None)
            user_id = data.get('user_id', None)
            list_type = data.get('list_type', 'recruitment')
            if list_type == 'recruitment':
                list_id = data.get('recruitment')
            else:
                list_id = data.get('prospection')
            SavedListProfiles.objects.create(
                list_id = int(list_id),
                profile_id = int(record_id)
            )
            return JsonResponse({'success': True, 'message': 'Profile added to the list'}, status=201)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


# Temporary view to delete all location data
@super_admin_required
def delete_all_cities_data(request):
    LocationDetails.objects.all().delete()
    return redirect('/')

@csrf_exempt
def get_list_candidates(request, pk):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')

            saved_profiles = SavedListProfiles.objects.filter(list=pk).order_by("-created_at")
            profile_ids = saved_profiles.values_list('profile_id', flat=True)
            records = CandidateProfiles.objects.filter(id__in=profile_ids)
            context['list_id'] = pk
            context['list_name'] = SavedLists.objects.get(pk=pk).name

            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')
            
            search_query =  Q(full_name__icontains=search_params) | Q(email1__icontains=search_params) | Q(email2__icontains=search_params) | Q(company_name__icontains=search_params) | Q(headline__icontains=search_params) | Q(current_position__icontains=search_params) | Q(person_skills__icontains=search_params) | Q(person_city__icontains=search_params) | Q(person_state__icontains=search_params) | Q(person_country__icontains=search_params) 
            records = records.filter(search_query)
            
            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = paginator.count

            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records

            actions = Actions.objects.filter(parent_user_id=user_id).order_by('-id')
            actions_mapping = {}
            for action in actions:
                if action.profile_id not in actions_mapping:
                    actions_mapping[action.profile_id] = []
                actions_mapping[action.profile_id].append({
                    'action_type': action.get_action_type_display(),
                    'action_type_value': action.action_type,
                    'parent_user': action.parent_user_id,
                    'action_user': action.action_user_id,
                    'comment': action.comment,
                    'action_datetime': action.action_datetime,
                    'id': action.id
                })

            # Construct the list of records with additional info
            records_list = []
            for record in page_obj.object_list:
                # Fetch visibility toggle for each candidate profile
                visibility_toggle = ProfileVisibilityToggle.objects.filter(candidate=record, search_user_id=user_id).first()

                candidate_dict = {
                    'id': record.id,
                    'full_name': record.full_name,
                    'first_name': record.first_name,
                    'last_name': record.last_name,
                    'headline': record.headline,
                    'current_position': record.current_position,
                    'company_name': record.company_name,
                    'person_city': record.person_city,
                    'person_state': record.person_state,
                    'person_country': record.person_country,
                    'person_industry': record.person_industry,
                    'tags': record.tags,
                    'person_skills': record.person_skills,
                    'education_experience': record.education_experience,
                    'company_website': record.company_website,
                    'email1': record.email1,
                    'email2': record.email2,
                    'phone1': record.phone1,
                    'phone2': record.phone2,
                    'person_linkedin_url': record.person_linkedin_url,
                    'company_size_from': record.company_size_from,
                    'company_size_to': record.company_size_to,
                    'current_position_2': record.current_position_2,
                    'current_company_2': record.current_company_2,
                    'previous_position_2': record.previous_position_2,
                    'previous_company_2': record.previous_company_2,
                    'previous_position_3': record.previous_position_3,
                    'previous_company_3': record.previous_company_3,
                    'company_city': record.company_city,
                    'company_state': record.company_state,
                    'company_country': record.company_country,
                    'person_angellist_url': record.person_angellist_url,
                    'person_crunchbase_url': record.person_crunchbase_url,
                    'person_twitter_url': record.person_twitter_url,
                    'person_facebook_url': record.person_facebook_url,
                    'company_linkedin_url': record.company_linkedin_url,
                    'person_image_url': record.person_image_url,
                    'company_logo_url': record.company_logo_url,
                    'show_email1': visibility_toggle.show_email1 if visibility_toggle else False,
                    'show_email2': visibility_toggle.show_email2 if visibility_toggle else False,
                    'show_phone1': visibility_toggle.show_phone1 if visibility_toggle else False,
                    'show_phone2': visibility_toggle.show_phone2 if visibility_toggle else False,
                    'is_favourite': visibility_toggle.is_favourite if visibility_toggle else False,
                    'is_in_list': SavedListProfiles.objects.filter(profile=record).exists(),
                    'actions': actions_mapping.get(record.id, []),
                    'is_saved': CandidateProfiles.is_saved_for_user(record.id, user_id)
                }
                records_list.append(candidate_dict)

            context['records'] = records_list
            return JsonResponse(context, status=200)
        except json.JSONDecodeError:
            context['success'] = False
            context['message'] = 'Invalid JSON format!'
            return JsonResponse(context, status=400)
        except SavedLists.DoesNotExist:
            context['success'] = False
            context['message'] = 'Saved list not found!'
            return JsonResponse(context, status=404)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    context['success'] = False
    context['message'] = 'Invalid request method!'
    return JsonResponse(context, status=405)



@csrf_exempt
def remove_record_from_list(request):
    context = {}
    if request.method == "POST":
        try:
            body = json.loads(request.body)
            list_id = body.get("list_id", None)
            candidate_id = body.get("record_id", None)

            if not list_id or not candidate_id:
                context['success'] = False
                context['message'] = 'list_id and record_id are required'
                return JsonResponse(context, status=400)

            record = SavedListProfiles.objects.filter(list_id=list_id, profile_id=candidate_id)
            if record.exists():
                record.delete()
                context['success'] = True
                context['message'] = 'Record deleted successfully'
            else:
                context['success'] = False
                context['message'] = 'Record not found'
        except json.JSONDecodeError:
            context['success'] = False
            context['message'] = 'Invalid JSON format'
            return JsonResponse(context, status=400)
        except Exception as e:
            context['success'] = False
            context['message'] = f'Something bad happened: {str(e)}'
            return JsonResponse(context, status=500)
    else:
        context['success'] = False
        context['message'] = 'Invalid request method'
        return JsonResponse(context, status=405)

    return JsonResponse(context)


@csrf_exempt
def remove_candidate_from_list(request):
    context = {}
    if request.method == "POST":
        try:
            body = json.loads(request.body)
            user_id = body.get("user_id", None)
            candidate_id = body.get("record_id", None)

            if not user_id or not candidate_id:
                context['success'] = False
                context['message'] = 'list_id and record_id are required'
                return JsonResponse(context, status=400)

            record = SavedListProfiles.objects.filter(list__list_user_id=user_id,profile_id=candidate_id)
            if record.exists():
                record.delete()
                context['success'] = True
                context['message'] = 'Record deleted successfully'
            else:
                context['success'] = False
                context['message'] = 'Record not found'
        except json.JSONDecodeError:
            context['success'] = False
            context['message'] = 'Invalid JSON format'
            return JsonResponse(context, status=400)
        except Exception as e:
            context['success'] = False
            context['message'] = f'Something bad happened: {str(e)}'
            return JsonResponse(context, status=500)
    else:
        context['success'] = False
        context['message'] = 'Invalid request method'
        return JsonResponse(context, status=405)

    return JsonResponse(context)


@csrf_exempt
def add_actions(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            type = data.get('type', None)
            datetime = data.get('datetime', None)
            comment = data.get('comment', '')
            profile_id = data.get('profile', None)
            parent_id = data.get('parent', None)
            action_user_id = data.get('action_user', None)
            
            if type == None:
                return JsonResponse({'success': False, 'message': 'Action type is required'}, status=400)
            if profile_id == None:
                return JsonResponse({'success': False, 'message': 'Profile ID is required'}, status=400)
            if parent_id == None:
                return JsonResponse({'success': False, 'message': 'Parent user is required'}, status=400)
            if action_user_id == None:
                return JsonResponse({'success': False, 'message': 'Action user is required'}, status=400)
            else:
                new_action = Actions.objects.create(action_type=type, parent_user_id=parent_id, action_user_id=action_user_id, profile_id=profile_id, comment=comment, action_datetime=datetime)
                new_action_data = {
                    'action_type': new_action.get_action_type_display(),
                    'action_type_value': new_action.action_type,
                    'parent_user': new_action.parent_user_id,
                    'action_user': new_action.action_user_id,
                    'comment': new_action.comment,
                    'action_datetime': new_action.action_datetime,
                    'id': new_action.id
                }
            return JsonResponse({'success': True, 'message': 'Action created', 'actions': new_action_data}, status=201)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@csrf_exempt
def actions(request, id):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            type = data.get('type', None)
            datetime = data.get('datetime', None)
            comment = data.get('comment', '')
            parent_id = data.get('parent', None)
            action_user_id = data.get('action_user', None)

            try:
                action = Actions.objects.get(id=id, parent_user_id=parent_id, action_user_id=action_user_id)
            except Exception as e:
                action = None
            
            if action == None:
                return JsonResponse({'success': False, 'message': 'Action not found'}, status=404)
            if type == None:
                return JsonResponse({'success': False, 'message': 'Action type is required'}, status=400)
            else:
                action.action_type = type
                action.action_datetime = datetime
                action.comment = comment
                action.save(update_fields=['action_type', 'action_datetime', 'comment'])
                updated_action_data = {
                    'action_type': action.get_action_type_display(),
                    'action_type_value': action.action_type,
                    'parent_user': action.parent_user_id,
                    'action_user': action.action_user_id,
                    'comment': action.comment,
                    'action_datetime': action.action_datetime,
                    'id': action.id
                }
            return JsonResponse({'success': True, 'message': 'Action updated', 'actions': updated_action_data}, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    
    if request.method == "DELETE":
        try:
            try:
                action = Actions.objects.get(id=int(id))
            except Exception as e:
                action = None
            if action is None:
                return JsonResponse({'success': False, 'message': 'Action not found'}, status=404)
            action.delete()
            return JsonResponse({'success': True, 'message': 'Action deleted'}, status=204)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
        
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@csrf_exempt
def share_profile(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            profile_id = data.get('profile', None)
            shared_from = data.get('shared_from', None)
            shared_to = data.get('shared_to', None)
            
            if profile_id == None:
                return JsonResponse({'success': False, 'message': 'Profile ID is required'}, status=400)
            if shared_from == None:
                return JsonResponse({'success': False, 'message': 'Shared from user is required'}, status=400)
            if shared_to == None:
                return JsonResponse({'success': False, 'message': 'Shared to user is required'}, status=400)
            else:
                shared_profile = SharedProfiles.objects.update_or_create(shared_from=shared_from, shared_to=shared_to, profile_id=profile_id, defaults={})
            return JsonResponse({'success': True, 'message': 'Profile shared'}, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@csrf_exempt
def get_shared_to_list(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')

            filter_dict = query_dict.get('filter_data')
            share_user_ids = filter_dict.get('shared_users', [])
            start_date = filter_dict.get('start_date', None)
            end_date = filter_dict.get('end_date', None)
            city = filter_dict.get('city', '')
            state = filter_dict.get('state', '')
            region = filter_dict.get('region', '')
            country = filter_dict.get('country', '')

            records = SharedProfiles.objects.filter(shared_to=user_id, deleted_by_shared_to=False).select_related('profile').order_by('-id')
            
            if search_params:
                records = records.filter(Q(profile__first_name__icontains=search_params) | Q(profile__last_name__icontains=search_params) | Q(profile__current_position__icontains=search_params) | Q(profile__company_name__icontains=search_params))

            if len(share_user_ids) > 0:
                records = records.filter(shared_from__in=share_user_ids)
            if start_date:
                records = records.filter(created_at__gte=start_date)
            if end_date:
                records = records.filter(created_at__lte=end_date)
            
            if city:
                records = records.filter(Q(profile__person_city__icontains=city))
            if region:
                records = records.filter(Q(profile__person_state__icontains=region))
            # if country:
            #     records = records.filter(Q(profile__person_country__icontains=country))

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = paginator.count

            records_list = []
            for record in page_obj.object_list:
                visibility_toggle = ProfileVisibilityToggle.objects.filter(candidate=record.profile, search_user_id=user_id).first()
                profile_data = {
                    'id': record.id,
                    'shared_from': record.shared_from,
                    'shared_to': record.shared_to,
                    'created_at': record.created_at,
                    'updated_at': record.updated_at,
                    'profile': {
                        'id': record.profile.id,
                        'full_name': record.profile.full_name,
                        'first_name': record.profile.first_name,
                        'last_name': record.profile.last_name,
                        'headline': record.profile.headline,
                        'current_position': record.profile.current_position,
                        'company_name': record.profile.company_name,
                        'person_city': record.profile.person_city,
                        'person_state': record.profile.person_state,
                        'person_country': record.profile.person_country,
                        'person_industry': record.profile.person_industry,
                        'tags': record.profile.tags,
                        'person_skills': record.profile.person_skills,
                        'education_experience': record.profile.education_experience,
                        'company_website': record.profile.company_website,
                        'email1': record.profile.email1,
                        'email2': record.profile.email2,
                        'phone1': record.profile.phone1,
                        'phone2': record.profile.phone2,
                        'person_linkedin_url': record.profile.person_linkedin_url,
                        'company_size_from': record.profile.company_size_from,
                        'company_size_to': record.profile.company_size_to,
                        'current_position_2': record.profile.current_position_2,
                        'current_company_2': record.profile.current_company_2,
                        'previous_position_2': record.profile.previous_position_2,
                        'previous_company_2': record.profile.previous_company_2,
                        'previous_position_3': record.profile.previous_position_3,
                        'previous_company_3': record.profile.previous_company_3,
                        'company_city': record.profile.company_city,
                        'company_state': record.profile.company_state,
                        'company_country': record.profile.company_country,
                        'person_angellist_url': record.profile.person_angellist_url,
                        'person_crunchbase_url': record.profile.person_crunchbase_url,
                        'person_twitter_url': record.profile.person_twitter_url,
                        'person_facebook_url': record.profile.person_facebook_url,
                        'company_linkedin_url': record.profile.company_linkedin_url,
                        'person_image_url': record.profile.person_image_url,
                        'company_logo_url': record.profile.company_logo_url,
                        'show_email1': visibility_toggle.show_email1 if visibility_toggle else False,
                        'show_email2': visibility_toggle.show_email2 if visibility_toggle else False,
                        'show_phone1': visibility_toggle.show_phone1 if visibility_toggle else False,
                        'show_phone2': visibility_toggle.show_phone2 if visibility_toggle else False,
                        'is_favourite': visibility_toggle.is_favourite if visibility_toggle else False,
                        'is_in_list': SavedListProfiles.objects.filter(profile=record.profile).exists(),
                    }
                }
                records_list.append(profile_data)
            
            context['records'] = records_list
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            # context['records'] = list(page_obj.object_list.values())
            return JsonResponse(context, status=200)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@csrf_exempt
def get_shared_from_list(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')

            filter_dict = query_dict.get('filter_data')
            share_user_ids = filter_dict.get('shared_users', [])
            start_date = filter_dict.get('start_date', None)
            end_date = filter_dict.get('end_date', None)
            city = filter_dict.get('city', '')
            state = filter_dict.get('state', '')
            region = filter_dict.get('region', '')
            country = filter_dict.get('country', '')

            records = SharedProfiles.objects.filter(shared_from=user_id, deleted_by_shared_from=False).select_related('profile').order_by('-id')
            
            if search_params:
                records = records.filter(Q(profile__first_name__icontains=search_params) | Q(profile__last_name__icontains=search_params) | Q(profile__current_position__icontains=search_params) | Q(profile__company_name__icontains=search_params))

            if len(share_user_ids) > 0:
                records = records.filter(shared_to__in=share_user_ids)
            if start_date:
                records = records.filter(created_at__gte=start_date)
            if end_date:
                records = records.filter(created_at__lte=end_date)
            
            if city:
                records = records.filter(Q(profile__person_city__icontains=city))
            if region:
                records = records.filter(Q(profile__person_state__icontains=region))
            # if country:
            #     records = records.filter(Q(profile__person_country__icontains=country))

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = paginator.count

            records_list = []
            for record in page_obj.object_list:
                visibility_toggle = ProfileVisibilityToggle.objects.filter(candidate=record.profile, search_user_id=user_id).first()
                profile_data = {
                    'id': record.id,
                    'shared_from': record.shared_from,
                    'shared_to': record.shared_to,
                    'created_at': record.created_at,
                    'updated_at': record.updated_at,
                    'profile': {
                        'id': record.profile.id,
                        'full_name': record.profile.full_name,
                        'first_name': record.profile.first_name,
                        'last_name': record.profile.last_name,
                        'headline': record.profile.headline,
                        'current_position': record.profile.current_position,
                        'company_name': record.profile.company_name,
                        'person_city': record.profile.person_city,
                        'person_state': record.profile.person_state,
                        'person_country': record.profile.person_country,
                        'person_industry': record.profile.person_industry,
                        'tags': record.profile.tags,
                        'person_skills': record.profile.person_skills,
                        'education_experience': record.profile.education_experience,
                        'company_website': record.profile.company_website,
                        'email1': record.profile.email1,
                        'email2': record.profile.email2,
                        'phone1': record.profile.phone1,
                        'phone2': record.profile.phone2,
                        'person_linkedin_url': record.profile.person_linkedin_url,
                        'company_size_from': record.profile.company_size_from,
                        'company_size_to': record.profile.company_size_to,
                        'current_position_2': record.profile.current_position_2,
                        'current_company_2': record.profile.current_company_2,
                        'previous_position_2': record.profile.previous_position_2,
                        'previous_company_2': record.profile.previous_company_2,
                        'previous_position_3': record.profile.previous_position_3,
                        'previous_company_3': record.profile.previous_company_3,
                        'company_city': record.profile.company_city,
                        'company_state': record.profile.company_state,
                        'company_country': record.profile.company_country,
                        'person_angellist_url': record.profile.person_angellist_url,
                        'person_crunchbase_url': record.profile.person_crunchbase_url,
                        'person_twitter_url': record.profile.person_twitter_url,
                        'person_facebook_url': record.profile.person_facebook_url,
                        'company_linkedin_url': record.profile.company_linkedin_url,
                        'person_image_url': record.profile.person_image_url,
                        'company_logo_url': record.profile.company_logo_url,
                        'show_email1': visibility_toggle.show_email1 if visibility_toggle else False,
                        'show_email2': visibility_toggle.show_email2 if visibility_toggle else False,
                        'show_phone1': visibility_toggle.show_phone1 if visibility_toggle else False,
                        'show_phone2': visibility_toggle.show_phone2 if visibility_toggle else False,
                        'is_favourite': visibility_toggle.is_favourite if visibility_toggle else False,
                        'is_in_list': SavedListProfiles.objects.filter(profile=record.profile).exists(),
                    }
                }
                records_list.append(profile_data)
            
            context['records'] = records_list
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            # context['records'] = list(page_obj.object_list.values())
            return JsonResponse(context, status=200)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@csrf_exempt
def delete_shared_profile(request, pk):
    if request.method == "POST":
        try:
            query_dict = json.loads(request.body)
            shared_to = query_dict.get('shared_to', None)
            shared_from = query_dict.get('shared_from', None)
            current_user = query_dict.get('current_user', None)
            try:
                profile_instance = SharedProfiles.objects.get(id=pk, shared_to=shared_to, shared_from=shared_from)
            except Exception as e:
                print(e)
                profile_instance = None
            
            if profile_instance == None:
                return JsonResponse({'success': False, 'message': 'Shared profile not found'}, status=404)
            elif profile_instance.deleted_by_shared_from == True or profile_instance.deleted_by_shared_from == True:
                profile_instance.delete()
            elif shared_to == current_user:
                profile_instance.deleted_by_shared_to = True
                profile_instance.save(update_fields=['deleted_by_shared_to'])
            elif shared_from == current_user:
                profile_instance.deleted_by_shared_from = True
                profile_instance.save(update_fields=['deleted_by_shared_from'])
            return JsonResponse({'success': True, 'message': 'Shared profile deleted'}, status=204)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
    
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@csrf_exempt
def get_profile(request, pk):
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')
            record = CandidateProfiles.objects.get(id=pk)
            visibility_toggle = ProfileVisibilityToggle.objects.filter(candidate=record, search_user_id=user_id).first()
            
            actions = Actions.objects.filter(parent_user_id=user_id).order_by('-id')
            actions_mapping = {}
            for action in actions:
                if action.profile_id not in actions_mapping:
                    actions_mapping[action.profile_id] = []
                actions_mapping[action.profile_id].append({
                    'action_type': action.get_action_type_display(),
                    'action_type_value': action.action_type,
                    'parent_user': action.parent_user_id,
                    'action_user': action.action_user_id,
                    'comment': action.comment,
                    'action_datetime': action.action_datetime,
                    'id': action.id
                })

            profile = {
                'id': record.id,
                'full_name': record.full_name,
                'first_name': record.first_name,
                'last_name': record.last_name,
                'headline': record.headline,
                'current_position': record.current_position,
                'company_name': record.company_name,
                'person_city': record.person_city,
                'person_state': record.person_state,
                'person_country': record.person_country,
                'person_industry': record.person_industry,
                'tags': record.tags,
                'person_skills': record.person_skills,
                'education_experience': record.education_experience,
                'company_website': record.company_website,
                'email1': record.email1,
                'email2': record.email2,
                'phone1': record.phone1,
                'phone2': record.phone2,
                'person_linkedin_url': record.person_linkedin_url,
                'company_size_from': record.company_size_from,
                'company_size_to': record.company_size_to,
                'current_position_2': record.current_position_2,
                'current_company_2': record.current_company_2,
                'previous_position_2': record.previous_position_2,
                'previous_company_2': record.previous_company_2,
                'previous_position_3': record.previous_position_3,
                'previous_company_3': record.previous_company_3,
                'company_city': record.company_city,
                'company_state': record.company_state,
                'company_country': record.company_country,
                'person_angellist_url': record.person_angellist_url,
                'person_crunchbase_url': record.person_crunchbase_url,
                'person_twitter_url': record.person_twitter_url,
                'person_facebook_url': record.person_facebook_url,
                'company_linkedin_url': record.company_linkedin_url,
                'person_image_url': record.person_image_url,
                'company_logo_url': record.company_logo_url,
                'show_email1': visibility_toggle.show_email1 if visibility_toggle else False,
                'show_email2': visibility_toggle.show_email2 if visibility_toggle else False,
                'show_phone1': visibility_toggle.show_phone1 if visibility_toggle else False,
                'show_phone2': visibility_toggle.show_phone2 if visibility_toggle else False,
                'is_favourite': visibility_toggle.is_favourite if visibility_toggle else False,
                'is_in_list': SavedListProfiles.objects.filter(profile=record).exists(),
                'actions': actions_mapping.get(record.id, []),
                'is_saved': CandidateProfiles.is_saved_for_user(record.id, user_id)
            }
            return JsonResponse({'success': True, 'message': 'Profile retrieved', 'profile': profile}, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Profile not found'}, status=404)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)


@csrf_exempt
def get_activities_list(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            parent_user_id = query_dict.get('parent_user')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')

            filter_dict = query_dict.get('filter_data')
            activity_user_ids = filter_dict.get('activity_users', [])
            start_date = filter_dict.get('start_date', None)
            end_date = filter_dict.get('end_date', None)
            city = filter_dict.get('city', '')
            state = filter_dict.get('state', '')
            region = filter_dict.get('region', '')
            country = filter_dict.get('country', '')
            action_type = filter_dict.get('action_type', '')

            records = Actions.objects.filter(parent_user_id=parent_user_id).select_related('profile').order_by('-id')
            
            if search_params:
                records = records.filter(Q(profile__first_name__icontains=search_params) | Q(profile__last_name__icontains=search_params) | Q(profile__current_position__icontains=search_params) | Q(profile__company_name__icontains=search_params))

            if len(activity_user_ids) > 0:
                records = records.filter(action_user_id__in=activity_user_ids)
            if start_date:
                records = records.filter(created_at__gte=start_date)
            if end_date:
                records = records.filter(created_at__lte=end_date)
            
            if city:
                records = records.filter(Q(profile__person_city__icontains=city))
            if region:
                records = records.filter(Q(profile__person_state__icontains=region))
            # if country:
            #     records = records.filter(Q(profile__person_country__icontains=country))

            if action_type:
               records = records.filter(Q(action_type=action_type)) 

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()
            total_records = paginator.count

            records_list = []
            for record in page_obj.object_list:
                visibility_toggle = ProfileVisibilityToggle.objects.filter(candidate=record.profile, search_user_id=parent_user_id).first()
                profile_data = {
                    'id': record.id,
                    'action_type': record.get_action_type_display(),
                    'created_by': record.action_user_id,
                    'created_at': record.created_at,
                    'updated_at': record.updated_at,
                    'profile': {
                        'id': record.profile.id,
                        'full_name': record.profile.full_name,
                        'first_name': record.profile.first_name,
                        'last_name': record.profile.last_name,
                        'headline': record.profile.headline,
                        'current_position': record.profile.current_position,
                        'company_name': record.profile.company_name,
                        'person_city': record.profile.person_city,
                        'person_state': record.profile.person_state,
                        'person_country': record.profile.person_country,
                        'person_industry': record.profile.person_industry,
                        'tags': record.profile.tags,
                        'person_skills': record.profile.person_skills,
                        'education_experience': record.profile.education_experience,
                        'company_website': record.profile.company_website,
                        'email1': record.profile.email1,
                        'email2': record.profile.email2,
                        'phone1': record.profile.phone1,
                        'phone2': record.profile.phone2,
                        'person_linkedin_url': record.profile.person_linkedin_url,
                        'company_size_from': record.profile.company_size_from,
                        'company_size_to': record.profile.company_size_to,
                        'current_position_2': record.profile.current_position_2,
                        'current_company_2': record.profile.current_company_2,
                        'previous_position_2': record.profile.previous_position_2,
                        'previous_company_2': record.profile.previous_company_2,
                        'previous_position_3': record.profile.previous_position_3,
                        'previous_company_3': record.profile.previous_company_3,
                        'company_city': record.profile.company_city,
                        'company_state': record.profile.company_state,
                        'company_country': record.profile.company_country,
                        'person_angellist_url': record.profile.person_angellist_url,
                        'person_crunchbase_url': record.profile.person_crunchbase_url,
                        'person_twitter_url': record.profile.person_twitter_url,
                        'person_facebook_url': record.profile.person_facebook_url,
                        'company_linkedin_url': record.profile.company_linkedin_url,
                        'person_image_url': record.profile.person_image_url,
                        'company_logo_url': record.profile.company_logo_url,
                        'show_email1': visibility_toggle.show_email1 if visibility_toggle else False,
                        'show_email2': visibility_toggle.show_email2 if visibility_toggle else False,
                        'show_phone1': visibility_toggle.show_phone1 if visibility_toggle else False,
                        'show_phone2': visibility_toggle.show_phone2 if visibility_toggle else False,
                        'is_favourite': visibility_toggle.is_favourite if visibility_toggle else False,
                        'is_in_list': SavedListProfiles.objects.filter(profile=record.profile).exists(),
                    }
                }
                records_list.append(profile_data)
            
            context['records'] = records_list
            
            context['start_record'] = 0 if total_records == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if total_records == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = total_records
            return JsonResponse(context, status=200)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)
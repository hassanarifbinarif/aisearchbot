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
from aisearchbot.helpers import send_verification_code_email, send_account_credentials_email
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.forms import AuthenticationForm, AdminPasswordChangeForm, PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.shortcuts import render, redirect
from django.utils import timezone
from asb.priorities import keyword_with_job_title_or_skill
from .models import CandidateProfiles, DuplicateProfiles, LocationDetails, ProfileVisibilityToggle, SavedListProfiles, SavedLists, User, OTP, SharedUsers, SavedListProfiles
from .forms import UserChangeForm, CustomUserCreationForm
from django.conf import settings
from aisearchbot.decorators import super_admin_required
from django.views.decorators.csrf import csrf_exempt
from django.db.models.functions import Lower
from operator import or_


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
    context['active_sidebar'] = 'dashboard'
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

def replace_chars_in_file(file):
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
        df = pd.read_csv(file, dtype=str)
        
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
                
                cleaned_data, status = replace_chars_in_file(file)
                if not status['success']:
                    return JsonResponse(status, status=400)
                
                if file_extension in ['.xlsx', '.xls']:
                    df = pd.concat(cleaned_data.values(), ignore_index=True)
                else:
                    df = cleaned_data

                df.fillna('', inplace=True)
                
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

                new_instances = []
                duplicate_instances = []
                is_duplicate = False

                for index, row in df.iterrows():
                    profile_data = {}
                    for column_name_in_df, field_name_in_model in column_map_lower.items():
                        value = row.get(column_name_in_df, None)
                        if field_name_in_model == 'person_skills' and value:
                            value = value.split(',')
                        if (field_name_in_model == 'company_size_from' or field_name_in_model == 'company_size_to') and value:
                            value = int(float(value))
                        if value == '':
                            value = None
                        profile_data[field_name_in_model] = value
                    
                    email = profile_data['email1']
                    email2 = profile_data['email2']
                    linkedin_url = profile_data['person_linkedin_url']
                    try:
                        original_profile = CandidateProfiles.objects.filter(person_linkedin_url=linkedin_url).first()
                        if email is not None:
                            if not original_profile:
                                original_profile = CandidateProfiles.objects.filter(Q(email1=email) | Q(email2=email), email1__isnull=False).first()
                            if not original_profile:
                                original_profile = CandidateProfiles.objects.filter(Q(email1=email) | Q(email2=email), email2__isnull=False).first()
                        if email2 is not None:    
                            if not original_profile:
                                original_profile = CandidateProfiles.objects.filter(Q(email1=email2) | Q(email2=email2), email1__isnull=False).first()
                            if not original_profile:
                                original_profile = CandidateProfiles.objects.filter(Q(email1=email2) | Q(email2=email2), email2__isnull=False).first()
                        if original_profile:
                            profile_data['original_profile'] = original_profile
                            duplicate_instances.append(profile_data)
                            is_duplicate = True
                        else:
                            new_instances.append(CandidateProfiles(**profile_data))
                    except CandidateProfiles.DoesNotExist:
                        new_instances.append(CandidateProfiles(**profile_data))
                
                CandidateProfiles.objects.bulk_create(new_instances)
                
                DuplicateProfiles.objects.all().delete()
                for duplicate_data in duplicate_instances:
                    DuplicateProfiles.objects.update_or_create(email1=duplicate_data['email1'], defaults=duplicate_data)
                    
                return JsonResponse({'success': True, 'message': 'Data uploaded', 'is_duplicate': is_duplicate}, status=200)
            return JsonResponse({'success': False, 'message': 'File not found'}, status=400)
        except Exception as e:
            print(e)
            return JsonResponse({'success': False, 'message': 'Something bad happened'}, status=500)
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
        context['user_count'] = users.count()
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
        paginator = Paginator(users, 12)
        page_obj = paginator.get_page(page_number)
        context['current_page'] = page_obj.number
        context['total_pages'] = paginator.num_pages
        context['has_next'] = page_obj.has_next()
        context['has_previous'] = page_obj.has_previous()
        text_template = loader.get_template('ajax/manage-conflict-table.html')
        html = text_template.render({'page_obj':page_obj, 'field_names': context['field_names'], 'search_params': search_params, 'current_page': context['current_page'], 'total_pages': context['total_pages']})
        context['html'] = html
        context['msg'] = 'Successfully retrieved registered users'
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
                matching_locations = LocationDetails.objects.filter(match_query)
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
                        # company_size_query |= Q(company_size_from__gte=size_from, company_size_to__lte=size_to)
                        company_size_query |= Q(company_size_from__range=(size_from, size_to))
                valid_data_query = Q(company_size_to__isnull=True) | Q(company_size_from__lte=F('company_size_to'))
                records = records.filter(company_size_query & valid_data_query)

            # Apply contact details filter
            if len(contact_details) > 0:
                query = Q()
                field_mapping = {'email1': 'email1', 'email2': 'email2', 'phone1': 'phone1', 'phone2': 'phone2'}
                operation = query_dict.get('contact_details_radio', 'or')
                for field in contact_details:
                    if field in field_mapping:
                        q = Q(**{f"{field_mapping[field]}__isnull": False})
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
            # key_q = build_keyword_query(keywords, ['headline', 'current_position'], use_advanced=use_advanced_search)
            # j_s_queries = build_keyword_query(job_skill_list, ['headline', 'current_position'], ['person_skills'])
            j_queries = build_keyword_query(job_titles, ['headline', 'current_position'])
            s_queries = build_keyword_query(skills, [], ['person_skills'])
            
            if keywords != '':
                priority_4 = records.filter(keyword_query).annotate(priority=Value(5, output_field=IntegerField()))
            elif len(job_titles) > 0:
                priority_4 = records.filter(j_queries).annotate(priority=Value(5, output_field=IntegerField()))
            elif len(skills) > 0:
                priority_4 = records.filter(s_queries).annotate(priority=Value(5, output_field=IntegerField()))
            else:
                priority_4 = records
                # priority_4 = records.filter(j_s_queries).annotate(priority=Value(5, output_field=IntegerField()))

            # # For priority 3
            # if keywords != '':
            #     priority_4 = priority_4.annotate(
            #         priority=Case(
            #             When(key_q & combined_keyword_query, then=Value(4)),
            #             output_field=IntegerField(),
            #         )
            #     )
            #     # priority_4 = priority_4.filter(key_q & combined_keyword_query).annotate(priority=Value(3, output_field=IntegerField()))
            # else:
            #     if combined_keyword_query != Q():
            #         priority_4 = priority_4.annotate(
            #             priority=Case(
            #                 When(combined_keyword_query, then=Value(4)),
            #                 output_field=IntegerField(),
            #             )
            #         )

            # # For priority 2
            # if len(skills) == 0:
            #     if keywords != '':
            #         priority_4 = priority_4.annotate(
            #             priority=Case(
            #                 When(Q(headline__icontains=keywords) | Q(current_position__icontains=keywords) | Q(person_skills__icontains=keywords), then=Value(3)),
            #                 output_field=IntegerField(),
            #             )
            #         )
            # else:
            #     priority_2_conditions = priority_4.model.objects.case_insensitive_skills_search(skills)
            #     priority_4 = priority_4.annotate(
            #         priority=Case(
            #             When(priority_2_conditions, then=Value(3)),
            #             output_field=IntegerField(),
            #         )
            #     )
            #     # priority_2 = priority_4.case_insensitive_skills_search(skills)


            ab = priority_4

            if ((keywords != '' and len(job_titles) > 0) or (keywords != '' and len(skills) > 0) or (len(job_titles) > 0 and len(skills) > 0)) and use_advanced_search == False:
                ab = keyword_with_job_title_or_skill(priority_4, keywords, job_titles, skills)


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

            # Apply job title filter
            # if len(job_titles) == 0:
            #     if keywords != '':
            #         priority_4 = priority_4.annotate(
            #             priority=Case(
            #                 When(key_q, then=Value(1)),
            #                 output_field=IntegerField(),
            #             )
            #         )
            # else:
            #     job_title_queries = build_keyword_query(job_titles, ['headline', 'current_position'])
            #     priority_4 = priority_4.annotate(
            #         priority=Case(
            #             When(key_q & job_title_queries, then=Value(1)),
            #             output_field=IntegerField(),
            #         )
            #     )
            
            # if keywords != '' and use_advanced_search == False and (len(job_titles) > 0 or len(skills) > 0):
            #     priority_4 = keyword_with_job_title_or_skill(priority_4)
            
            
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
            city_codes = matching_locations.values_list('city_code', flat=True)

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
                Q(personCountry__icontains=search_params) |
                Q(personCity__icontains=normalized_location_string) |
                Q(personState__icontains=normalized_location_string) |
                Q(personCountry__icontains=normalized_location_string) |
                Q(personCity__icontains=hyphenated_location_string) |
                Q(personState__icontains=hyphenated_location_string) |
                Q(personCountry__icontains=hyphenated_location_string) |
                Q(personCity__in=city_labels) |
                Q(personState__in=city_labels) |
                Q(personCountry__in=city_labels) |
                Q(personCity__in=normalized_city_labels) |
                Q(personState__in=normalized_city_labels) |
                Q(personCountry__in=normalized_city_labels) |
                Q(personCity__in=hyphenated_city_labels) |
                Q(personState__in=hyphenated_city_labels) |
                Q(personCountry__in=hyphenated_city_labels) |
                Q(personCity__in=city_codes) |
                Q(personState__in=city_codes) |
                Q(personCountry__in=city_codes)
            )

            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()

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
            
            context['start_record'] = 0 if records.count() == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if records.count() == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = records.count()
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
                candidate_dict['show_email1'] = item.show_email1
                candidate_dict['show_email2'] = item.show_email2
                candidate_dict['show_phone1'] = item.show_phone1
                candidate_dict['show_phone2'] = item.show_phone2
                candidate_dict['is_favourite'] = item.is_favourite
                candidate_dict['is_opened'] = False
                if candidate_dict['show_email1'] or candidate_dict['show_email2'] or candidate_dict['show_phone1'] or candidate_dict['show_phone2']:
                        candidate_dict['is_opened'] = True
                page_obj_list.append(candidate_dict)
            
            context['start_record'] = 0 if records.count() == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if records.count() == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = records.count()
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

@super_admin_required
def delete_all_candidates(request):
    CandidateProfiles.objects.all().delete()
    return redirect('/')


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
                SavedLists.objects.create(list_user_id=user_id, name=list_name, list_type=list_type)
            return JsonResponse({'success': True, 'message': 'List created'}, status=201)
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

            # Fetch saved profiles for the given list
            saved_profiles = SavedListProfiles.objects.filter(list=pk).order_by("-created_at")
            profile_ids = saved_profiles.values_list('profile_id', flat=True)
            records = CandidateProfiles.objects.filter(id__in=profile_ids)
            context['list_id'] = pk
            context['list_name'] = SavedLists.objects.get(pk=pk).name

            # Pagination
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')   
            
            search_query =  Q(full_name__icontains=search_params) | Q(email1__icontains=search_params) | Q(email2__icontains=search_params) | Q(company_name__icontains=search_params) | Q(headline__icontains=search_params) | Q(current_position__icontains=search_params) | Q(person_skills__icontains=search_params) | Q(person_city__icontains=search_params) | Q(person_state__icontains=search_params) | Q(person_country__icontains=search_params) 
            records = records.filter(search_query)  # Apply search query to the filtered records
            
            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()

            context['start_record'] = 0 if records.count() == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if records.count() == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = records.count()

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
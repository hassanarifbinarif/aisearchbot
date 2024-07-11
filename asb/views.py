import json
import os
import operator
import pandas as pd
from django.template import loader
from collections import Counter
from django.db.models import Q, F
from functools import reduce
from django.core.exceptions import ObjectDoesNotExist
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
from .models import CandidateProfiles, DuplicateProfiles, LocationDetails, ProfileVisibilityToggle, SavedListProfiles, SavedLists, User, OTP, SharedUsers, SavedListProfiles
from .forms import UserChangeForm, CustomUserCreationForm
from django.conf import settings
from aisearchbot.decorators import super_admin_required
from django.views.decorators.csrf import csrf_exempt
from django.db.models.functions import Lower
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector


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
    'Å‚': 'ł', 'Å„': 'ń', 'Å¡': 'š', 'Å¸': 'Ÿ', 'Å¾': 'ž'
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
                        if value == '':
                            value = None
                        profile_data[field_name_in_model] = value
                    
                    email = profile_data['email1']
                    try:
                        original_profile = CandidateProfiles.objects.filter(email1=email).first()
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
        paginator = Paginator(users, 12)
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



def filter_location(location, records, allow_null_first_iteration=False):
    normalized_location_string = location.replace('-', ' ')
    hyphenated_location_string = location.replace(' ', '-')
    matching_locations = LocationDetails.objects.filter(
        Q(region_name__icontains=location) | Q(region_name__icontains=normalized_location_string) | 
        Q(region_name__icontains=hyphenated_location_string) | Q(department_name__icontains=location) |
        Q(department_name__icontains=normalized_location_string) | Q(department_name__icontains=hyphenated_location_string)
    )
    city_labels = matching_locations.values_list('label', flat=True)
    city_codes = matching_locations.values_list('city_code', flat=True)

    normalized_city_labels = []
    hyphenated_city_labels = []
    for label in city_labels:
        normalized_city_labels.append(label.replace('-', ' ').lower())
        hyphenated_city_labels.append(label.replace(' ', '-').lower())

    location_filter_query = Q(personCity__icontains=location) | Q(personState__icontains=location) | Q(personCountry__icontains=location) | Q(personCity__icontains=normalized_location_string) | Q(personState__icontains=normalized_location_string) |Q(personCountry__icontains=normalized_location_string) | Q(personCity__icontains=hyphenated_location_string) | Q(personState__icontains=hyphenated_location_string) | Q(personCountry__icontains=hyphenated_location_string) | Q(personCity__in=city_labels) | Q(personState__in=city_labels) | Q(personCountry__in=city_labels) | Q(personCity__in=normalized_city_labels) | Q(personState__in=normalized_city_labels) | Q(personCountry__in=normalized_city_labels) | Q(personCity__in=hyphenated_city_labels) | Q(personState__in=hyphenated_city_labels) | Q(personCountry__in=hyphenated_city_labels) | Q(personCity__in=city_codes) | Q(personState__in=city_codes) | Q(personCountry__in=city_codes)

    if allow_null_first_iteration:
        location_filter_query |= Q(personCity__isnull=True) | Q(personState__isnull=True) | Q(personCountry__isnull=True)
    
    records = records.filter(location_filter_query)

    return records


def update_country(records, location):
    if ',' in location:
        words = [word.strip() for word in location.split(',')]
        for i, word in enumerate(words):
            normalized_location_string = word.replace('-', ' ')
            hyphenated_location_string = word.replace(' ', '-')
            for record in records:
                if not record['person_country']:
                    matching_location = LocationDetails.objects.filter(
                        Q(city_code__iexact=record['person_city']) |
                        Q(city_code__iexact=record['person_state']) |
                        Q(city_code__iexact=location) |
                        Q(city_code__iexact=normalized_location_string) |
                        Q(city_code__iexact=hyphenated_location_string) |
                        Q(label__iexact=record['person_city']) |
                        Q(label__iexact=record['person_state']) |
                        Q(label__iexact=location) |
                        Q(label__iexact=normalized_location_string) |
                        Q(label__iexact=hyphenated_location_string)
                    ).first()
                    if matching_location:
                        record['person_country'] = matching_location.region_name.title()
                    else:
                        record['person_country'] = record['person_state']
    else:
        normalized_location_string = []
        hyphenated_location_string = []
        location = [loc.lower() for loc in location]
        for loc in location:
            normalized_location_string.append(loc.replace('-', ' '))
            hyphenated_location_string.append(loc.replace(' ', '-'))
        # normalized_location_string = location.replace('-', ' ')
        # hyphenated_location_string = location.replace(' ', '-')
        for record in records:
            if not record['person_country']:
                match_query = Q()
                for loc in location:
                    match_query |= (
                        Q(city_code__iexact=loc) |
                        Q(label__iexact=loc)
                    )
                for loc in normalized_location_string:
                    match_query |= (
                        Q(city_code__iexact=loc) |
                        Q(label__iexact=loc)
                    )
                for loc in hyphenated_location_string:
                    match_query |= (
                        Q(city_code__iexact=loc) |
                        Q(label__iexact=loc)
                    )
                match_query |= (Q(city_code__iexact=record['person_city']) | Q(city_code__iexact=record['person_state']) | Q(label__iexact=record['person_city']) | Q(label__iexact=record['person_state']))
                matching_location = LocationDetails.objects.filter(match_query).first()
                print(matching_location.region_name)
                if matching_location:
                    record['person_country'] = matching_location.region_name.title()
                else:
                    record['person_country'] = record['person_state']
    return records


@csrf_exempt
def search_profile(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            print(query_dict)
            # {'keywords': '', 'location': ['Rhône', 'Lille'], 'contact_details_radio': 'or', 'contact_name': '', 'size_from': 'null', 'size_to': 'null', 'skills_list': [], 'jobs_title_list': [], 'company_name_list': [], 'contact_details': [], 'company_size_ranges': [], 'page': 1, 'user_id': 2}
            user = query_dict.get('user_id', None)
            
            keywords = query_dict.get('keywords', '')
            location = query_dict.get('location', '')
            company_size_from = query_dict.get('size_from', None)
            company_size_to = query_dict.get('size_to', None)
            
            if company_size_from == "" or company_size_from == "null":
                company_size_from = None
            if company_size_to == "" or company_size_to == "null":
                company_size_to = None
            
            search_fields = [
                'id', 'full_name', 'first_name', 'last_name', 'headline', 'current_position',
                'company_name', 'person_city', 'person_state', 'person_country', 'person_industry',
                'tags', 'person_skills', 'education_experience', 'company_website', 'email1',
                'email2', 'phone1', 'phone2', 'person_linkedin_url', 'company_size_from',
                'company_size_to', 'current_position_2', 'current_company_2', 'previous_position_2',
                'previous_company_2', 'previous_position_3', 'previous_company_3', 'company_city',
                'company_state', 'company_country', 'person_angellist_url', 'person_crunchbase_url',
                'person_twitter_url', 'person_facebook_url', 'company_linkedin_url', 'person_image_url','company_logo_url'
            ]

            records = CandidateProfiles.objects.all().order_by('-id')

            records = records.annotate(lower_company_name=Lower('company_name'), personCity=Lower('person_city'), personState=Lower('person_state'), personCountry=Lower('person_country'))
            records = records.filter(
                        Q(headline__icontains=keywords) |
                        Q(current_position__icontains=keywords)
                    )
            if ',' in location:
                words = [word.strip() for word in location.split(',')]
                words.reverse()
                for i, word in enumerate(words):
                    allow_null = (i == 0)
                    normalized_location_string = word.replace('-', ' ')
                    hyphenated_location_string = word.replace(' ', '-')
                    records = filter_location(word, records, allow_null_first_iteration=allow_null)
            else:
                normalized_location_string = []
                hyphenated_location_string = []
                location = [loc.lower() for loc in location]
                for loc in location:
                    normalized_location_string.append(loc.replace('-', ' '))
                    hyphenated_location_string.append(loc.replace(' ', '-'))
                match_query = Q()
                for loc in location:
                    match_query |= (
                        Q(region_name__iexact=loc) |
                        Q(department_name__iexact=loc)
                    )
                for loc in normalized_location_string:
                    match_query |= (
                        Q(region_name__iexact=loc) |
                        Q(department_name__iexact=loc)
                    )
                for loc in hyphenated_location_string:
                    match_query |= (
                        Q(region_name__iexact=loc) |
                        Q(department_name__iexact=loc)
                    )
                # matching_locations = LocationDetails.objects.annotate(lower_region_name=Lower('region_name'), lower_department_name=Lower('department_name')).filter(
                #     Q(lower_region_name__in=location) | Q(lower_region_name__in=normalized_location_string) | 
                #     Q(lower_region_name__in=hyphenated_location_string) | Q(lower_department_name__in=location) |
                #     Q(lower_department_name__in=normalized_location_string) | Q(lower_department_name__in=hyphenated_location_string)
                # )
                matching_locations = LocationDetails.objects.filter(match_query)
                city_labels = matching_locations.values_list('label', flat=True)
                city_codes = matching_locations.values_list('city_code', flat=True)

                normalized_city_labels = []
                hyphenated_city_labels = []
                for label in city_labels:
                    normalized_city_labels.append(label.replace('-', ' ').lower())
                    hyphenated_city_labels.append(label.replace(' ', '-').lower())

                records = records.filter(
                        Q(personCity__in=location) |
                        Q(personState__in=location) |
                        Q(personCountry__in=location) |
                        Q(personCity__in=normalized_location_string) |
                        Q(personState__in=normalized_location_string) |
                        Q(personCountry__in=normalized_location_string) |
                        Q(personCity__in=hyphenated_location_string) |
                        Q(personState__in=hyphenated_location_string) |
                        Q(personCountry__in=hyphenated_location_string) |
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
                # for ab in records:
                #     print(ab.person_city, ab.person_state, ab.person_country)
            records = records.case_insensitive_skills_search(query_dict.get('skills_list', []))
            
            job_titles = query_dict.get('jobs_title_list', [])
            if len(job_titles) > 0:
                job_title_queries = [Q(headline__icontains=term) | Q(current_position__icontains=term) for term in job_titles]
                job_query = job_title_queries.pop()
                for q in job_title_queries:
                    job_query |= q
                records = records.filter(job_query)

            company_names = query_dict.get('company_name_list', [])
            if len(company_names) > 0:
                company_name_queries = [Q(company_name__icontains=term) for term in company_names]
                company_name_query = company_name_queries.pop()
                for q in company_name_queries:
                    company_name_query |= q
                records = records.filter(company_name_query)

            contact_details = query_dict.get('contact_details', [])
            if len(contact_details) > 0:
                query = Q()
                field_mapping = {
                    'email1': 'email1',
                    'email2': 'email2',
                    'phone1': 'phone1',
                    'phone2': 'phone2'
                }
                operation = query_dict.get('contact_details_radio', 'or')
                for field in contact_details:
                    if field in field_mapping:
                        q = Q(**{f"{field_mapping[field]}__isnull": False})
                        if operation == 'or':
                            query |= q
                        elif operation == 'and':
                            query &= q
                records = records.filter(query)
                
            company_size_ranges = query_dict.get('company_size_ranges', [])
            if len(company_size_ranges) > 0:
                company_size_query = Q()
                for range in company_size_ranges:
                    size_from = range.get('from')
                    size_to = range.get('to')

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
                valid_data_query = Q(company_size_to__isnull=True) | Q(company_size_from__lte=F('company_size_to'))
                records = records.filter(company_size_query & valid_data_query)

            records = records.filter(
                Q(full_name__icontains=query_dict.get('contact_name', '')) |
                Q(first_name__icontains=query_dict.get('contact_name', '')) |
                Q(last_name__icontains=query_dict.get('contact_name', ''))
            )
            
            page_number = query_dict.get("page", 1)
            records_per_page = 20
            paginator = Paginator(records, records_per_page)
            page_obj = paginator.get_page(page_number)
            context['current_page'] = page_obj.number
            context['total_pages'] = paginator.num_pages
            context['has_next'] = page_obj.has_next()
            context['has_previous'] = page_obj.has_previous()

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
            
            page_obj = update_country(page_obj, location)

            context['start_record'] = 0 if records.count() == 0 else (page_number - 1) * records_per_page + 1
            context['end_record'] = 0 if records.count() == 0 else context['start_record'] + len(page_obj) - 1
            context['success'] = True
            context['records_count'] = records.count()
            context['records'] = page_obj
            return JsonResponse(context, status=200)
            

        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happed!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


@csrf_exempt
def toggle_visibility(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get('user', None)
            record_id = data.get('record_id', None)
            # show_email1 = data.get('show_email1', False)
            # show_email2 = data.get('show_email2', False)
            # show_phone1 = data.get('show_phone1', False)
            # show_phone2 = data.get('show_phone2', False)
            
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
def get_recruitment_list(request):
    context = {}
    if request.method == 'POST':
        try:
            query_dict = json.loads(request.body)
            user_id = query_dict.get('user_id')

            records = SavedLists.objects.filter(list_user_id=int(user_id), list_type=SavedLists.Types.RECRUITMENT).order_by('-id')
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')

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
            context['records'] = list(page_obj.object_list.values())
            return JsonResponse(context, status=200)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happed!'
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
            context['records'] = list(page_obj.object_list.values())
            return JsonResponse(context, status=200)
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happed!'
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
            context['list_name'] = SavedLists.objects.get(pk=pk).name

            # Pagination
            page_number = query_dict.get("page", 1)
            search_params = query_dict.get("q", '')

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
        except Exception as e:
            print(e)
            context['success'] = False
            context['message'] = 'Something bad happened!'
            return JsonResponse(context, status=500)

    return JsonResponse(context)


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

from django.urls import path
from . import views

urlpatterns = [
    
    #authentication
    path('login/', views.super_admin_login, name='super_admin_login'),
    path('logout/', views.super_admin_logout, name='super_admin_logout'),
    path('send-otp/', views.send_otp, name='super_admin_send_otp'),
    path('verify-code/', views.verify_code, name='super_admin_login_verify_code'),
    path('reset-password/', views.reset_password, name='super_admin_login_reset_password'),
    
    #dashboard
    path('', views.dashboard, name='super_admin_login_dashboard'),
    path('manage-conflicts/', views.manage_conflicts, name='manage-conflicts'),
    
    #accounts
    path('account/', views.account, name='account'),
    path('update-personal-info/', views.update_personal_info, name='update_personal_info'),
    path('update-password/', views.update_password, name='update_password'),
    
    #users
    path('users/', views.users, name='users'),
    path('add-user/', views.add_user, name='add_users'),
    path('suspend-user/<pk>', views.suspend_user, name='suspend_user'),
    path('activate-user/<pk>', views.activate_user, name='activate_user'),
    path('delete-user/<pk>', views.delete_user, name='delete_user'),

    path('import-data/', views.import_file_data, name='import_file_data'),
    path('export-data/', views.export_file_data, name='export_file_data'),

    path('get-candidate-data/<str:params>/', views.get_candidate_data, name='get_candidate_data'),
    path('get-duplicate-data/<str:params>/', views.get_duplicate_data, name='get_duplicate_data'),
    path('resolve-conflict/', views.resolve_conflict, name='resolve_conflict'),

    path('search-matching-profile/', views.search_profile, name='search_matching_profile'),

    path('toggle-visibility/', views.toggle_visibility, name='toggle_visibility'),

    path('delete-candidates/', views.delete_all_candidates, name='delete_all_candidates'),
    path('delete-duplicates/', views.delete_all_duplicates, name='delete_all_duplicates'),
]
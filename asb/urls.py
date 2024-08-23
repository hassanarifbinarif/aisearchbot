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
    path('keep-recent-records/', views.keep_recent_records, name='keep_recent_records'),

    path('search-matching-profile/', views.search_profile, name='search_matching_profile'),

    path('toggle-visibility/', views.toggle_visibility, name='toggle_visibility'),

    path('get-favourite-profiles/', views.get_favourite_profiles, name='get_favourite_profiles'),
    path('get-opened-profiles/', views.get_opened_profiles, name='get_opened_profiles'),

    path('del-candidate/<int:pk>/', views.delete_specific_candidates, name='delete_specific_candidates'),

    # path('delete-candidates/', views.delete_all_candidates, name='delete_all_candidates'),
    path('delete-duplicates/', views.delete_all_duplicates, name='delete_all_duplicates'),

    path('upload-location-data/', views.location_data_upload, name='location_data_upload'),
    path('del-location-data/', views.delete_all_cities_data, name='delete_all_cities_data'),

    #saved lists
    path('add-list/', views.add_list, name='add_list'),
    path('delete-list/', views.delete_list, name='delete_list'),
    path("update-list/", views.update_list, name="update_list"),
    
    path('get-recruitment-list/', views.get_recruitment_list, name='get_recruitment_list'),
    path('get-prospection-list/', views.get_prospection_list, name='get_prospection_list'),

    path('add-record-in-list/', views.add_record_in_list, name='add_record_in_list'),
    path('remove-record-from-list/', views.remove_record_from_list, name='remove_record_from_list'),
    path('remove-candidate-from-list/', views.remove_candidate_from_list, name='remove_candidate_from_list'),
    path('get-list-candidates/<int:pk>', views.get_list_candidates, name='get_list_candidates'),
    # path('grouped-profiles-view/', views.match_profiles_in_batches, name='grouped_profiles_view')

    path('add-actions/', views.add_actions, name='add_actions'),
    path('actions/<int:id>/', views.actions, name='actions_methods'),

    path('share-profile/', views.share_profile, name='share_profile'),
    path('get-shared-to-list/', views.get_shared_to_list, name='get_shared_to_list'),
    path('get-shared-from-list/', views.get_shared_from_list, name='get_shared_from_list'),
    path('delete-shared-profile/<int:pk>/', views.delete_shared_profile, name='delete_shared_profile'),
]
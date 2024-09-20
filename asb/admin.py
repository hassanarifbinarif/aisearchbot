from django.contrib import admin
from . models import SavedListProfiles, SavedLists, Need
# Register your models here.

admin.site.register(SavedListProfiles)
admin.site.register(SavedLists)
admin.site.register(Need)

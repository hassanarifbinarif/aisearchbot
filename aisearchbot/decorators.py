from django.shortcuts import redirect
from functools import wraps


def super_admin_required(function):
    def wrap(request, *args, **kwargs):
        if not request.user.is_superuser:
            return redirect('/login')
        else:
            return function(request, *args, **kwargs)
    return wrap
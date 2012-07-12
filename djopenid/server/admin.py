#!/usr/local/bin/python2.7
#coding:utf-8

from .models import AuthSites
from django.contrib import admin
from django.contrib.auth.models import User

def site_permission(obj):
    if obj.permission == 1:
        return 'always allowed'
    return 'not allowd'
site_permission.short_description = 'permisson'

def site_user(obj):
    user = User.objects.get(id=obj.uid)
    return user.username
site_user.short_description = 'user'

class AuthSitesAdmin(admin.ModelAdmin):
    def queryset(self, request):
        qs = super(AuthSitesAdmin, self).queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(uid=request.user.id)

    def save_model(self, request, obj, form, change):
        obj.uid = request.user.id
        obj.permission = 1
        obj.save()

    fields = ('site', )
    list_display = ('site', site_user, site_permission)

admin.site.register(AuthSites, AuthSitesAdmin)

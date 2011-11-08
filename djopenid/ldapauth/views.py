#coding:utf-8

from djopenid import util
from djopenid.server import views as s_views
from djopenid.util import getViewURL
from django import http
from django.views.generic.simple import direct_to_template

def login(request):
    if request.method == 'GET':
        referer = request.META.get('HTTP_REFERER', '')
        if request.session.get('ldap_login', None):
            return http.HttpResponseRedirect(getViewURL(request, s_views.server))
        return direct_to_template(request, 'server/login.html', {'ret': '', 'referer': referer, 'url': '/auth/'})
    else:
        user, passwd = request.POST.get('user', None), request.POST.get('passwd', None)
        referer = request.POST.get('referer', None)
        remember = request.POST.get('remember', '')
        if not util.authWithLdap(request, user, passwd):
            return direct_to_template(request, 'server/login.html', {'ret': 'error', 'url': '/auth/'})
        print remember
        if remember == '':
            print '******'
            request.session.set_expiry(0)
        if not referer:
            return http.HttpResponseRedirect(getViewURL(request, s_views.server))
        return http.HttpResponseRedirect(referer)

def logout(request):
    util.cleanSession(request)
    return direct_to_template(request, 'server/login.html', {'ret': 'logout', 'url': '/auth/'})

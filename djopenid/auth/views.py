#coding:utf-8

from django import http
from django.views.generic.simple import direct_to_template
from django.contrib.auth import authenticate, login, logout

from djopenid import util
from djopenid.util import getViewURL
from djopenid.server import views as s_views

def sign_in(request):
    if request.method == 'GET':
        next_url = request.GET.get('next', '')
        if request.user.is_authenticated():
            return http.HttpResponseRedirect(getViewURL(request, s_views.server))
        return direct_to_template(request, 'server/login.html', {'ret': '', 'next': next_url, 'url': '/auth/'})
    else:
        user, passwd = request.POST.get('user', None), request.POST.get('passwd', None)
        next_url = request.POST.get('next', None)
        remember = request.POST.get('remember', '')
        user = authenticate(username=user, password=passwd)
        if not user:
            return direct_to_template(request, 'server/login.html', {'ret': 'error', 'next': next_url, 'url': '/auth/'})
        login(request, user)
        if not next_url:
            return http.HttpResponseRedirect(getViewURL(request, s_views.server))
        return http.HttpResponseRedirect(next_url)

def sign_out(request):
    logout(request)
    return direct_to_template(request, 'server/login.html', {'ret': 'logout', 'url': '/auth/'})

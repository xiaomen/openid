#coding:utf-8

from djopenid import util
from djopenid.server import views as s_views
from djopenid.util import getViewURL
from django import http
from django.views.generic.simple import direct_to_template

from doubanldap import DoubanLDAP

def login(request):
    if request.method == 'GET':
        referer = request.META.get('HTTP_REFERER', '')
        if request.session.get('ldap_login', None):
            return http.HttpResponseRedirect(getViewURL(request, s_views.server))
        return direct_to_template(request, 'server/login.html', {'ret': '', 'referer': referer})
    else:
        user, passwd = request.POST.get('user', None), request.POST.get('passwd', None)
        referer = request.POST.get('referer', None)
        ldap_check = DoubanLDAP()
        try:
            ldap_check.bind(user, passwd)
            request.session['ldap_login'] = 1
            request.session['ldap_info'] = ldap_check.searchuserbyid(user)[0]
            request.session['ldap_uid'] = user
            if not referer:
                return http.HttpResponseRedirect(getViewURL(request, s_views.server))
            return http.HttpResponseRedirect(referer)
        except:
            import traceback
            traceback.print_exc()
            return direct_to_template(request, 'server/login.html', {'ret': 'error'})

def logout(request):
    try:
        for k in request.session.keys():
            if k.startswith('ldap'):
                del request.session[k]
    except:
        pass
    return direct_to_template(request, 'server/login.html', {'ret': 'logout'})

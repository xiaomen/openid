#coding:utf-8

from django.conf.urls.defaults import *

urlpatterns = patterns(
    'djopenid.ldapauth.views',
    (r'^$', 'login'),
    (r'^logout/$', 'logout'),
)

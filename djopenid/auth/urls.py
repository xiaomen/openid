#coding:utf-8

from django.conf.urls.defaults import *

urlpatterns = patterns(
    'djopenid.auth.views',
    (r'^$', 'sign_in'),
    (r'^logout/$', 'sign_out'),
)

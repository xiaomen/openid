
from django.conf.urls.defaults import *

urlpatterns = patterns(
    'djopenid.server.views',
    (r'^$', 'server'),
    (r'^xrds/$', 'idpXrds'),
    (r'^processTrustResult/$', 'processTrustResult'),
    (r'^endpoint/$', 'endpoint'),
    (r'^trust/$', 'trustPage'),
    (r'^delete/$', 'manager'),
    (r'^(?P<user>.*)/$', 'idPage'),
)

from django.conf.urls.defaults import *

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns(
    '',
    ('^$', 'djopenid.views.index'),
    ('^consumer/', include('djopenid.consumer.urls')),
    ('^server/', include('djopenid.server.urls')),
    ('^auth/', include('djopenid.auth.urls')),
    ('^admin/', include(admin.site.urls)),
)

import os
import sys
import traceback
from django.core.handlers.wsgi import WSGIHandler
from django.core.signals import got_request_exception
from django.core.management import call_command

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'djopenid'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'djopenid.settings'

def exception_printer(sender, **kwargs):
        traceback.print_exc()

got_request_exception.connect(exception_printer)
call_command('syncdb')
app = WSGIHandler()

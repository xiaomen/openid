#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'djopenid.settings'

import time
from djopenid.server.models import AuthSites

if __name__ == '__main__':
    fp = file('test.log', 'w')
    i = 0
    print >>fp, '\n'
    while True:
        print >>fp, 'starting...'
        # for row in AuthSites.objects.all():
        #     print >>fp, i, row.id
        #     fp.flush()
        print >>fp, 'done.\n'
        i += 1
        fp.flush()
        time.sleep(5)

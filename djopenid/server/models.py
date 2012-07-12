from django.db import models

class AuthSites(models.Model):
    uid = models.CharField(max_length=255)
    site = models.CharField(max_length=255)
    permission = models.PositiveSmallIntegerField(default=0)

    def __unicode__(self):
        return self.site

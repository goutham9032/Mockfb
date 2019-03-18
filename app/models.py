import time

import reversion

from django.contrib.auth.models import User
from django.db import models

@reversion.register()
class FeedActivity(models.Model):
    description = models.CharField(max_length=255, blank=True)
    file_location = models.CharField(max_length=255, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    slug = models.IntegerField(default=int(time.time()))
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    likes_count = models.IntegerField(default=0)
    like = models.BooleanField(default=False)

class OtpActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=255)
    created_ts = models.IntegerField(default=0)


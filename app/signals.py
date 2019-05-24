# Note****: dont forgot to import this file in app/apps.py and
# default_app_config = 'app.apps.AppConfig' in __init__.py

import time
import json
import requests

# django imports
from django.contrib.auth.models import User
from django.db.models.signals import post_save, pre_save, post_delete, pre_delete
from django.dispatch import receiver, Signal

# User defined imports
from app.models import FeedActivity, WebhooksActivity

# custom signals example
user_login = Signal(providing_args=["request", "user"])
def user_login_handler(sender, **kwargs):
    """signal intercept for user_login"""
    user = kwargs['user']
    print('in receivers pyton file %s'%(user))

user_login.connect(user_login_handler)

# django signals example
@receiver(pre_delete, sender=FeedActivity)
def signals_test_for_delete(sender, instance, **kwargs):
    print('instance deleted')


@receiver(pre_save, sender=FeedActivity)
def feedactivity_signals(sender, instance, **kwargs):
    hook = WebhooksActivity.objects.filter(user=instance.owner).order_by('-id').first()
    headers = {'X_Mockfb_delivery_id':int(time.time()), 'event': 'created'}
    if not instance._state.adding:
       print ('this is an update')
    else:
       print('this is insert')
       if hook.key:
          headers['X_HUB_SIGNATURE'] = hook.key
       data = { 'event':'created',
                'slug':instance.slug,
                'desc':instance.description,
              }
       try:
          # comment this if you want to create it from shell
          res = requests.post(url=hook.redirect_url, data=json.dumps(data),
                              headers=headers, timeout=20)
          if res.status_code == 200:
             print('webhook success')
       except requests.exceptions.ReadTimeout:
          print('time out error')


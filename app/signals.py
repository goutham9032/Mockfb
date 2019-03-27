# django imports
from django.contrib.auth.models import User
from django.db.models.signals import post_save, pre_save, post_delete, pre_delete
from django.dispatch import receiver, Signal

# User defined imports
from app.models import FeedActivity

# custom signals example
user_login = Signal(providing_args=["request", "user"])
def user_login_handler(sender, **kwargs):
    """signal intercept for user_login"""
    user = kwargs['user']
    print('in receivers pyton file %s'%(user))

user_login.connect(user_login_handler)

# django signals example
@receiver(pre_save, sender=FeedActivity)
def signals_test_for_feed(sender, instance, **kwargs):
    if not instance._state.adding:
       print ('this is an update')
    else:
       print ('this is an insert')

@receiver(pre_delete, sender=FeedActivity)
def signals_test_for_delete(sender, instance, **kwargs):
    print(dir(instance))

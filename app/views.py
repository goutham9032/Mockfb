import os
import json
import time
import urllib

from django.shortcuts import render, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib.sessions.models import Session
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm, PasswordChangeForm, PasswordResetForm, SetPasswordForm,
)
from .forms import UserRegistrationForm

from app.models import FeedActivity

log = settings.LOG
base_dir = settings.BASE_DIR

def get_user_from_session(req_perm):
    # https://overiq.com/django-1-10/django-logging-users-in-and-out/
    session = Session.objects.get(session_key=req_perm.session.session_key)
    session_data = session.get_decoded()
    uid = session_data.get('_auth_user_id')
    user = User.objects.get(id=uid)
    log.info('user_info_from_session',
              f_name='get_user_from_session',
              user_id=user.id, username=user.username)

@login_required
def home(request):
    log.info('home_page_opened',
             action_type="opened",
             f_name="home",
             time=int(time.time()))

    user = User.objects.get(id=request.user.id)
    feeds = FeedActivity.objects.all().order_by('-id')
    return render(request, 'home.html', { 'feeds': feeds , 'user': user})

@csrf_exempt
def feed_content(request):
    desc = request.GET.get('desc','')
    action = request.GET.get('action','')
    user = User.objects.first()
    uploaded_file_url = ''
    if request.method == 'POST' and request.FILES.get('myfile',''):
        myfile = request.FILES['myfile']
        fs = FileSystemStorage()
        filename = fs.save(myfile.name, myfile)
        uploaded_file_url = fs.url(filename)
        log.info('feed_content',
		 action_type="file_upoaded",
                 fn_name="feed_content",
		 time=int(time.time()),
                 file_location=uploaded_file_url)
    FeedActivity.objects.create(file_location=uploaded_file_url,
                                slug=int(time.time()),
                                owner=user,
                                description=desc)
    return HttpResponse('OK')

@csrf_exempt
def feed_activity(request):
    body = json.loads(request.body.decode())
    feed = FeedActivity.objects.filter(slug=int(body['feed_id']))

    log.info('feed_activity',
             action_type=body.get('action'),
             fn_name="feed_activity",
             slug=int(body['feed_id']),
             time=int(time.time()))

    if body.get('action') == 'like':
       likes = feed[0].likes_count + 1
       like = True
       feed.update(likes_count=likes, like=like)
       return JsonResponse({'success':True, 'likes':likes})
    elif body.get('action') == 'unlike':
       likes = feed[0].likes_count - 1
       like = False
       feed.update(likes_count=likes, like=like)
       return JsonResponse({'success':True, 'likes':likes})
    elif body.get('action') == 'delete':
       try:
          feed.delete()
          if feed[0].file_location:
              os.remove(base_dir+feed[0].file_location)
          return JsonResponse({'success':True})
       except:
          return JsonResponse({'success':False})
    elif body.get('action') == 'comment':
       # TODO : on comment store it in db
       pass
    else:
        pass

def register(request):
    if request.method == 'POST':
        post_body = request.POST.dict()
        username = post_body['username']
        email =  post_body['email']
        password = post_body['password']
        firstname = post_body['firstname']
        lastname = post_body['lastname']
        if not (User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists()):
            User.objects.create_user(username=username, email=email,
                                     password=password, first_name=firstname,
                                     last_name=lastname)
            user = authenticate(username = username, password = password)
            login(request, user)
            return HttpResponseRedirect('/')
        else:
            raise forms.ValidationError('Looks like a username with that email or password already exists')
    else:
        form = UserRegistrationForm()
    return render(request, 'registration/register.html', {'form' : form})

def login_user(request):
    # Note : please dont change function name as login, as login was already imported from djnago
    if request.method == 'POST':
        req = request.POST.dict()
        username = req.get('username','')
        password = req.get('password','')
        if not (User.objects.filter(username=username).exists() and password):
            return render(request, 'registration/login.html', {'success': False, 'data':req})
        user = authenticate(username = username, password = password)
        if 'remember' not in req:
            request.session.set_expiry(0)
            settings.SESSION_EXPIRE_AT_BROWSER_CLOSE = True
        else:
            settings.SESSION_EXPIRE_AT_BROWSER_CLOSE = False
        login(request, user)
        return HttpResponseRedirect('/')
    else:
        form = AuthenticationForm(request)
        return render(request, 'registration/login.html', {'success': True})


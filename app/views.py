import re
import os
import json
import time
import urllib
import base64
from random import randint

import reversion
from reversion.models import Version
from django.shortcuts import render, redirect
from django.conf import settings
from django_otp.oath import TOTP
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.contrib.sessions.models import Session
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.contrib.auth.hashers import make_password, check_password
from django.template.loader import render_to_string, get_template
from django import forms
from django.db.models import Q
from django import template
from django.contrib.auth.forms import (
    AuthenticationForm, PasswordChangeForm, PasswordResetForm, SetPasswordForm,
)
from .forms import UserRegistrationForm

from app.models import FeedActivity, OtpActivity
from app.signals import user_login

# 3rd party moduls
import arrow

log = settings.LOG
base_dir = settings.BASE_DIR
register = template.Library()

@register.filter
def split(val):
    return val.split(',')


def check_response_time(func):
    def inner_fun(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        total = time.time() - start
        log.info('Total_time_taken_for_response : %s'%(total),
                fn_name=func.__name__,
                request_type=args[0].method,
                status_code=res.status_code,
                headers=res._headers,
                url_path=args[0].build_absolute_uri())
        return res
    return inner_fun

def make_response():
   for i in range(0,10):
      yield i
      time.sleep(1)

@csrf_exempt
@check_response_time
def test_url(request):
    return HttpResponse('OK')

@csrf_exempt
def stream_data(request):
    return StreamingHttpResponse(make_response(), content_type="application/json")

def test_tags(request):
    return render(request, 'test_tags.html',{'lis':['a','b','c']})

def get_feed_dict(feed):
    get_time = lambda t_obj:arrow.get(t_obj).to('local').strftime("%Y-%m-%d %I:%M:%S %p %Z")
    return dict(desciption=feed.description,
                created_at=get_time(feed.created_at),
                updated_at=get_time(feed.updated_at),
                slug=feed.slug,
                likes=feed.likes_count,
                owner=dict(username=feed.owner.username,
                           email=feed.owner.email)
                )

@csrf_exempt
def create_feed(request):
    # Expected post request format in python
    # requests.post(url=<port_info>/api/v1/create_feed/', data={'description':'test'}, auth=(username, passwd)) or
    # requests.post(url=<port_info>/api/v1/create_feed/', data={'description':test}, headers={'Authorization':'Bearer <token>'})
    try:
        if 'HTTP_AUTHORIZATION' not in request.META:
            raise Exception('Invalid credentials')
        auth = request.META['HTTP_AUTHORIZATION'].split()
        auth_type, cred = auth[0].lower(), auth[1]
        if auth_type == 'basic':
            username, password = base64.b64decode(bytes(cred, 'utf-8')).decode().split(':')
            user = authenticate(username = username, password = password)
        elif auth_type == 'bearer':
            token = cred
            decoded_token = json.loads(base64.urlsafe_b64decode(token).decode())
            # validate for id and well as password key
            user = User.objects.filter(Q(id=decoded_token['user_id']) &
                                       Q(password__icontains=decoded_token['key']))
        if user:
           desc = request.POST.dict()['description']
           feed = FeedActivity.objects.create(file_location='',
                                             slug=int(time.time()),
                                             owner=user,
                                             description=desc)
           feed_dict = get_feed_dict(feed)
           return JsonResponse({'success':True, 'result': feed_dict})
        else:
           return JsonResponse({'success':False, 'message':'Invalid Credentials'})
    except:
        return JsonResponse({'success':False, 'message':'Invalid Credentials'})

@csrf_exempt
def get_all_feeds(request):
    # Expected url format /get_all_feeds?token=<access_token>
    token = request.GET.dict()
    try:
        if 'token' not in token:
           raise Exception('Invalid credentials')
        decoded_token = json.loads(base64.urlsafe_b64decode(token['token']).decode())
        user = User.objects.filter(Q(id=decoded_token['user_id']) &
                                   Q(password__icontains=decoded_token['key']))
        if user:
           feeds = FeedActivity.objects.filter(owner=user)
           return JsonResponse({'success':False, 'feeds':[get_feed_dict(feed) for feed in feeds]})
        else:
           raise Exception('Invalid credentials')
    except:
        return JsonResponse({'success':False, 'message':'Invalid Credentials'})

def get_user_from_session(req_perm):
    # https://overiq.com/django-1-10/django-logging-users-in-and-out/
    session = Session.objects.get(session_key=req_perm.session.session_key)
    session_data = session.get_decoded()
    uid = session_data.get('_auth_user_id')
    user = User.objects.get(id=uid)
    log.info('user_info_from_session',
              f_name='get_user_from_session',
              user_id=user.id, username=user.username)

def send_support_mail(subject, mail, body="", template_path='', context={}, cc_emails=[]):
    message = EmailMultiAlternatives(subject=subject,
        body=body, from_email=settings.EMAIL_HOST_USER,
        to=[mail], cc=cc_emails)

    template = render_to_string('email_template.html', context)
    message.attach_alternative(template, "text/html")
    try:
       message.send(fail_silently=False) #If u put true on fail also it returns 1
       return True
    except:
       return False

@check_response_time
@csrf_exempt
def update_feed_activity(request, slug):
    data = request.POST.dict()
    get_feed = lambda slug: FeedActivity.objects.get(slug=int(slug))
    get_versions = lambda obj: Version.objects.get_for_object(obj)
    with reversion.create_revision():
         # https://django-reversion.readthedocs.io/en/stable/api.html
         # Note : Update will not work, so use save
         feed = get_feed(slug)
         feed.description = data['description']
         feed.save()
         # reversion.set_user(request.user) # for testing remove this
         reversion.set_comment("V%s"%(get_versions(feed).count()+1))
    feed = get_feed(slug)
    all_versions_obj = get_versions(feed)
    all_versions = [{'comment':i.revision.comment,
                     'data': json.loads(i.serialized_data),
                     'id' : i.id,
                    } for i in all_versions_obj]
    return JsonResponse({'success':True, 'versions':all_versions})

@check_response_time
def password_reset(request, key):
    decoded_dict = json.loads(base64.urlsafe_b64decode(key).decode())
    user = User.objects.get(email=decoded_dict['email'])
    if decoded_dict['key'] != user.password.split('$')[-1]:
       return render(request, 'errors.html')
    if request.method == 'POST':
       req_body = request.POST.dict()
       new_enc_pass = req_body['new_password']
       new_dec_pass = base64.urlsafe_b64decode(bytes(new_enc_pass, 'utf-8')).decode()
       user.set_password(new_dec_pass)
       user.save()
       user = authenticate(username = user.username, password = new_dec_pass)
       if user:
          login(request, user)
          return JsonResponse({'success':True})
       else:
          return JsonResponse({'success':False})
    return render(request, 'registration/password_reset.html', {'user':user})


def get_passwd_reset_encoded_link(req, email, passwd):
    json_dumps = lambda email, key : json.dumps({'email':email,
                                                 'key':key.split('$')[-1],
                                                 'timestamp':int(time.time())})
    encode = lambda email, key: base64.urlsafe_b64encode(bytes(json_dumps(email, key), 'utf-8'))
    encoded_key = encode(email, passwd)
    home_url = req.get_raw_uri().split('accounts')[0]
    encoded_url = '%saccounts/password_reset/%s'%(home_url, encoded_key.decode())
    return encoded_url

@check_response_time
def forgot_password(request):
    if request.method == 'POST':
        post_body = request.POST.dict() # This format will be used when JSON is not stringified in js
        rand_no = lambda length : randint(int('1'*length),int('9'*length))
        if post_body['type'] == 'register_otp':
            try:
               user = User.objects.get(email=post_body['email'])
            except ObjectDoesNotExist:
                return JsonResponse({'success':False,
                                     'message': '<b>%s</b> email does not exists, please provide valid email'%(post_body['email'])})

            otp = rand_no(6)
            enc_otp = make_password(otp, '36000', 'pbkdf2_sha256')
            print(otp)
            # method2 storing in db
            OtpActivity.objects.update_or_create(user=user,
                                                defaults={'otp':enc_otp,
                                                          'created_ts':int(time.time())
                                                         })
            encoded_url = get_passwd_reset_encoded_link(req=request, email=user.email, passwd=user.password)
            email_pass_reset_msg = ' <br><br><a href="%s">Click here to reset password</a>'%(encoded_url)
            val = send_support_mail('[MockFb] Password Reset - %s'%(otp), post_body['email'], context={'otp':otp,
                                                                                   'email':post_body['email'],
                                                                                   'name':user.username,
                                                                                   'pass_reset_url': encoded_url})
            if val == 1:
               # method 1 setting to session some variables
               request.session['otp'] = otp
               request.session['expiry'] = int(time.time()) + settings.OTP_EXPIRY_LIMIT
               request.session['user'] = user.email
               # TODO : session not getting expired
               # request.session.set_expiry(settings.OTP_EXPIRY_LIMIT)
            success_msg = 'An OTP has been sent to the registered email <b>%s</b>'%(post_body['email'])
            return JsonResponse({'success':True, 'message': success_msg})
        elif post_body['type'] == 'verify_otp':
            # method 1 through session we can check
            sess_otp = request.session['otp']
            sess_otp_exp = request.session['expiry']
            sess_user = request.session['user']
            below_exp = int(time.time()) <= sess_otp_exp
            if not (below_exp and sess_user == post_body['email'] and post_body['otp'] == str(sess_otp)):
                return JsonResponse({'success':False})

            # method 2 store in deb and check
            user = User.objects.get(email=post_body['email'])
            obj = OtpActivity.objects.get(user=user)
            created_ts = obj.created_ts
            verified = check_password(post_body['otp'], obj.otp)
            pwd_reset_url = get_passwd_reset_encoded_link(req=request,
                                                          email=user.email,
                                                          passwd=user.password)
            if int(time.time()) <= created_ts + settings.OTP_EXPIRY_LIMIT and verified:
                # login(request, user) if we want we can login here only
                return JsonResponse({'success':True, 'pwd_reset_url': pwd_reset_url})
            else:
                return JsonResponse({'success':False})
    else:
       return render(request, 'registration/forgot_password.html')

@check_response_time
@login_required
def home(request):
    user_login.send(sender=None, request=request, user=request.user)
    log.info('home_page_opened',
             action_type="opened",
             f_name="home",
             time=int(time.time()))

    user = User.objects.get(id=request.user.id)
    feeds = FeedActivity.objects.all().order_by('-id')
    return render(request, 'home.html', { 'feeds': feeds , 'user': user})

@check_response_time
@login_required
def user_settings(request):
    user = User.objects.get(id=request.user.id)
    json_dumps = lambda _id, key : json.dumps({'user_id':_id,
                                                 'key':key.split('$')[-1],
                                                })
    encode_user_info = lambda _id, key: base64.urlsafe_b64encode(bytes(json_dumps(_id, key), 'utf-8'))
    token = encode_user_info(user.id, user.password).decode()
    return render(request, 'settings.html', { 'token': token ,'user': user})

@check_response_time
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
@check_response_time
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

@check_response_time
def register(request):
    if request.method == 'POST':
        post_body = request.POST.dict()
        username = post_body['username']
        email =  post_body['email']
        password = post_body['password']
        firstname = post_body['firstname']
        lastname = post_body['lastname']
        user_exists = User.objects.filter(username=username).exists()
        email_exists = User.objects.filter(email=email).exists()
        if not (user_exists or email_exists):
            # Note : when you create user , if we use .create it will store normal password
            # If we do create_user it will store sha256 password
            User.objects.create_user(username=username, email=email,
                                     password=password, first_name=firstname,
                                     last_name=lastname)
            user = authenticate(username = username, password = password)
            login(request, user)
            return HttpResponseRedirect('/')
        else:
            return render(request, 'registration/register.html', {'success':False,
                                                                 'user_exists':user_exists,
                                                                 'email_exists':email_exists,
                                                                 'data':post_body})
    else:
        form = UserRegistrationForm()
    return render(request, 'registration/register.html', {'form' : form, 'success':True})

@check_response_time
def login_user(request):
    # Note : please dont change function name as login, as login was already imported from djnago
    if request.method == 'POST':
        req = request.POST.dict()
        username = req.get('username','')
        password = req.get('password','')
        if not (User.objects.filter(username=username).exists() and password):
            return render(request, 'registration/login.html', {'success': False, 'data':req})
        user = authenticate(username = username, password = password)
        if not user:
            return render(request, 'registration/login.html', {'success': False, 'data':req})
        # TODO: session expire working in firefox, not in crome
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

@check_response_time
def fork_feed(slug, new_user_obj):
    '''
    This function will helps us to create/fork the same feed with different id, make sure
    to put pk as none so that it will create new id with same data in table
    '''
    feed = FeedActivity.objects.get(slug)
    feed.pk = None
    feed.slug = int(time.time())
    feed.owner = new_user_obj
    feed.save()


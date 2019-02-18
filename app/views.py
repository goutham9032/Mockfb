import json
import time

from django.shortcuts import render, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from app.models import FeedActivity

log = settings.LOG

def home(request):
    log.info('home_page_opened',
             action_type="opened",
             f_name="home",
             time=int(time.time()))
    user = User.objects.first()
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
          return JsonResponse({'success':True})
       except:
          return JsonResponse({'success':False})
    elif body.get('action') == 'comment':
       # TODO : on comment store it in db
       pass
    else:
        pass

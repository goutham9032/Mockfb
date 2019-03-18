from django.conf.urls import url, include
from django.conf import settings
from django.conf.urls.static import static

from . import views

urlpatterns = [
    url('^$', views.home, name='home'),
    url(r'^fileupload/$', views.feed_content, name='feed_content'),
    url(r'^activity/$', views.feed_activity, name='feed_activity'),
    url(r'^update_feed/(?P<slug>[\w-]+)$', views.update_feed_activity, name='update_feed_activity'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

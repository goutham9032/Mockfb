from django.conf.urls import url, include
from django.conf import settings
from django.conf.urls.static import static

from . import views

urlpatterns = [
    url('^$', views.home, name='home'),
    url(r'^fileupload/$', views.feed_content, name='feed_content'),
    url(r'^activity/$', views.feed_activity, name='feed_activity'),
    url(r'^settings/$', views.user_settings, name='user_settings'),
    url(r'^update_feed/(?P<slug>[\w-]+)$', views.update_feed_activity, name='update_feed_activity'),
    # testing
    url(r'^test_url/$', views.test_url, name='test_url'),
    url(r'^test_tags/$', views.test_tags, name='test_tags'),
    url(r'^stream_data/$', views.stream_data, name='stream_data'),
    # Api's
    url(r'^api/v1/create_feed/$', views.create_feed, name='create_feed'),
    url(r'^api/v1/get_all_feeds$', views.get_all_feeds, name='get_all_feeds'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

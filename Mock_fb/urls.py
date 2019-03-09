from django.conf.urls import url, include
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from app import views as app_views

urlpatterns = [

    url(r'^admin/', admin.site.urls),
    url(r'^accounts/login/$', app_views.login_user, name="login_user"),
    url(r'^accounts/logout/$', auth_views.logout, {'template_name':'registration/logout.html'}),
    url(r'^accounts/register/$', app_views.register, name="register"),
    url(r'^accounts/forgot_password/$', app_views.forgot_password, name="forgot_password"),
    url(r'^accounts/password_reset/(?P<key>.*)$', app_views.password_reset, name="password_reset"),

    url(r'^', include('app.urls')), # No need of import
]

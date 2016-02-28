"""manage URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin

from ip import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    #login interface
    #url(r'^accounts/login/$', 'django.contrib.auth.views.login'),
    #url(r'^accounts/logout/$', 'django.contrib.auth.views.logout'),
    #url(r'^accounts/register/$', 'accounts.views.register', name='register'),
    #url(r'^accounts/profile/$', 'django.views.generic.simple.direct_to_template', {'template':'registration/profile.html'}, name='user_profile'),
    url(r'^accounts/login/$', views.login),
    url(r'^accounts/logout/$', views.logout),
    url(r'^accounts/register/$', views.register),
    url(r'^$', views.frame_index),
    url(r'^frame/$', views.frame_index),
    url(r'^frame/(\d{1,10})/$', views.frame_subIndex),
    url(r'^frame/(\d{1,10})/(\d{1,10})/$', views.frame),
    url(r'^index/$', views.index),
    url(r'^site/$', views.site),
    url(r'^site/map/$', views.site_map),
    url(r'^site/classroom/$', views.site_classroom),
    url(r'^site/professor/$', views.site_professor),
    url(r'^site/research/$', views.site_research),
    url(r'^switch/$', views.switch),
    url(r'^switch/network/$', views.switch_network),
    url(r'^switch/(?P<machine>\d+)/$', views.switch_machine),
    url(r'^switch/p(?P<machine>\d+)/$', views.switch_port),
    #url(r'^switch/(?P<ip>\d+)/$', views.search_ip),
    url(r'^ip/$', views.ip),
    url(r'^ip/(?P<ip>\d+)/$',views.ip_ip),
    url(r'^special/$', views.special),
    url(r'^special/unusedip/$', views.special_unusedip),
    url(r'^special/search/$', views.special_search),
    url(r'^special/wrong/$', views.special_wrong),
    url(r'^management/$', views.management),
    url(r'^management/lock/$', views.management_lock),
]


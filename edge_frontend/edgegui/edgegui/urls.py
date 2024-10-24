"""
URL configuration for edgegui project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from edge.views import CustomLoginView, contact, logout_view, dashboard, download_logfile, ping, poweroff, restart
from django.views.generic import RedirectView
urlpatterns = [
    path('admin/', admin.site.urls),
    
    path('logout/', logout_view, name='logout'),
    path('contact/', contact, name='contact'),
    path('dashboard/', dashboard, name='dashboard'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('accounts/profile/', RedirectView.as_view(pattern_name='dashboard', permanent=True)),
    path('download-log/', download_logfile, name='download_logfile'),
    path('contact/<str:tab_name>/', contact, name='contact'),
    path('ping', ping, name='ping'),
    
    path('poweroff', poweroff, name='poweroff'),
    path('restart', restart, name='restart'),
]

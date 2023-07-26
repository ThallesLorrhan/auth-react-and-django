from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path('register', RegisterAPIViews.as_view()),
    path('login', LoginAPIViews.as_view()),
    path('user', UserAPIViews.as_view()),
    path('refresh', RefreshAPIViews.as_view()),
    path('logout', LogoutAPIViews.as_view()),
    path('forgot', ForgotAPIView.as_view()),
    path('reset', ResetAPIViews.as_view()),
]
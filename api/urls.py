from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from . import views


urlpatterns = [
    path('login', jwt_views.TokenObtainPairView.as_view(), name='login'),
    path('run', views.HelloView.as_view(), name='hello-world'),
    path('me', views.Extractor.as_view(), name='extract-token'),
]
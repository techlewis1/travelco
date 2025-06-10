from .views import VerifyEmailView
from django.urls import path
from .views import RegisterUserView, UserProfileView

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('verify-email/<uuid:token>/', VerifyEmailView.as_view(), name='email-verify'),
]
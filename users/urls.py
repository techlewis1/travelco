from django.urls import path
from .views import VerifyEmailView, RegisterUserView, UserProfileView, ResendVerificationView, DeleteAccountView, ReactivateAccountView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView

urlpatterns = [
    # User actions
    path('register/', RegisterUserView.as_view(), name='register'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('verify-email/<uuid:token>/', VerifyEmailView.as_view(), name='email-verify'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend-verification'),
    path('delete-account/', DeleteAccountView.as_view(), name='delete-account'),
    path('reactivate/', ReactivateAccountView.as_view(), name='reactivate-account'),

    # JWT Auth
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # login alias
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/logout/', TokenBlacklistView.as_view(), name='token_logout'),
]

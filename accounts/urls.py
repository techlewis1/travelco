from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("register/", views.register_page, name="register"),
    path("profile/", views.profile, name="profile"),
    path("reset-password/", views.password_reset_request, name="password_reset_request"),
    path("reset/<uidb64>/<token>/", views.password_reset_confirm, name="password_reset_confirm"),
    path('change-password/', views.change_password, name='change_password'),
]

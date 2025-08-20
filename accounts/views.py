from django.http import HttpResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.forms import SetPasswordForm
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import update_session_auth_hash
from .models import User, Profile


# Index
def index(request):
    return HttpResponse("Hello, world. You're at the accounts index.")


# Register
def register_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        password = request.POST['password']
        email = request.POST['email']

        if User.objects.filter(username=username).exists():
            return HttpResponse("Username already exists.")

        user = User.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email
        )
        user.set_password(password)
        user.save()
        return HttpResponse("User registered successfully.")
    return HttpResponse("Please register using the form.")


# Login
def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        if not User.objects.filter(username=username).exists():
            return HttpResponse("User does not exist.")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return HttpResponse("Logged in successfully.")
        return HttpResponse("Invalid credentials.")
    return HttpResponse("Please log in using the form.")


# Logout
def logout(request):
    auth_logout(request)
    return HttpResponse("Logged out successfully.")


# Profile (only logged in users)
@login_required
def profile(request):
    user = request.user
    return HttpResponse(f"Profile of {user.username}. Email: {user.email}.")

#password_change
def change_password(request):
    if request.method == 'POST':
        user = request.user
        old_password = request.POST.get('old_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')

        if not user.check_password(old_password):
            return HttpResponse("Old password is incorrect.", status=400)

        if new_password1 != new_password2:
            return HttpResponse("New passwords do not match.", status=400)

        user.set_password(new_password1)
        user.save()

        # Keep the user logged in after password change
        update_session_auth_hash(request, user)

        return HttpResponse("Password changed successfully.", status=200)

    return HttpResponse("Please submit the form to change your password.", status=405)


# Password Reset Request
def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = request.build_absolute_uri(f"/reset/{uid}/{token}/")

            send_mail(
                "Password Reset Request",
                f"Click the link to reset your password: {reset_link}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
            )
            return HttpResponse("Password reset email sent.")
        except User.DoesNotExist:
            return HttpResponse("No user with that email found.")
    return HttpResponse("Send a POST request with 'email' to reset password.")


# Password Reset Confirm
def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        return HttpResponse("Invalid reset link.")

    if not default_token_generator.check_token(user, token):
        return HttpResponse("Invalid or expired reset link.")

    if request.method == "POST":
        form = SetPasswordForm(user, request.POST)
        if form.is_valid():
            form.save()
            return HttpResponse("Password has been reset successfully.")
        return HttpResponse("Password reset failed. Try again.")

    return HttpResponse("Send a POST request with new password fields: new_password1, new_password2.")

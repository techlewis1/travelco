from django.shortcuts import render, redirect
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.decorators import login_required
from .forms import CustomUserCreationForm


def signup(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("login")  
    else:
        form = CustomUserCreationForm()
    return render(request, "users/signup.html", {"form": form})


class CustomLoginView(LoginView):
    template_name = "users/login.html"


class CustomLogoutView(LogoutView):
    template_name = "users/logout.html"


@login_required
def profile(request):
    return render(request, "users/profile.html")

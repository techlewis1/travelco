from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={"placeholder": "Enter your email"})
    )

    age = forms.IntegerField(
        required=True,
        min_value=0,
        label="Age"
    )

    preferred_travel_style = forms.ChoiceField(
        choices=[("", "---------")] + list(CustomUser._meta.get_field("preferred_travel_style").choices),
        required=True,
        label="Preferred Travel Style"
    )

    class Meta:
        model = CustomUser
        fields = ("username", "email", "age", "preferred_travel_style", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        for field in self.fields.values():
            field.help_text = None

    def clean_email(self):
        """Ensure email is unique (no duplicates allowed)."""
        email = self.cleaned_data.get("email")
        if email and CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("This email address is already registered.")
        return email

# base/validators.py

from django.core.exceptions import ValidationError
import re

class ComplexPasswordValidator:
    def validate(self, password, user=None):
        if not re.findall(r'[A-Z]', password):
            raise ValidationError("The password must contain at least one uppercase letter.")
        if not re.findall(r'[0-9]', password):
            raise ValidationError("The password must contain at least one digit.")
        if not re.findall(r'[!@#$%^&*(),.?\":{}|<>]', password):
            raise ValidationError("The password must contain at least one special character.")

    def get_help_text(self):
        return "Your password must contain at least one uppercase letter, one digit, and one special character."

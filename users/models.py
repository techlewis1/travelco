from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    age = models.PositiveIntegerField(
        null=True,
        blank=True,
        #help_text="Optional. Provide your age if you want."
    )
    preferred_travel_style = models.CharField(
        max_length=50,
        choices=[
            ('budget', 'Budget'),
            ('luxury', 'Luxury'),
            ('adventure', 'Adventure'),
            ('family', 'Family'),
            ('solo', 'Solo'),
        ],
        blank=True,
        null=True,
        #help_text="Optional. Choose your preferred travel style."
    )
    favorite_destinations = models.TextField(blank=True, null=True)
    travel_history = models.JSONField(blank=True, null=True) 

    def __str__(self):
        return self.username

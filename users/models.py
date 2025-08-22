from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    age = models.PositiveIntegerField(
        null=True,
        blank=True,
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
    )
    favorite_destinations = models.TextField(blank=True, null=True)
    travel_history = models.JSONField(blank=True, null=True) 

    def __str__(self):
        return self.username

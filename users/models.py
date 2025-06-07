from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    travel_preferences = models.JSONField(default=dict)
    favorites = models.JSONField(default=list)

    def __str__(self):
        return self.user.username
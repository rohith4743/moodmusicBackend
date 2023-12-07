from django.db import models
from django.contrib.auth.models import AbstractUser
import datetime


# Create your models here.

class MusicUser(AbstractUser):
    # Add any additional fields here
    # For example: bio = models.TextField(blank=True)
    username = models.TextField(primary_key=True)
    # id = models.AutoField(primary_key=True)
    pass

class SpotifyToken(models.Model):
    access_token = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_in = models.IntegerField()

    @property
    def is_expired(self):
        return datetime.datetime.now(datetime.timezone.utc) > self.created_at + datetime.timedelta(seconds=self.expires_in)
    
class SpotifyAccessToken(models.Model):
    access_token = models.CharField(max_length=255)
    refresh_token = models.CharField(max_length=255)
    expiry = models.DateTimeField()
    

class Profile(models.Model):
    username = models.CharField(max_length=100, primary_key=True)
    songs = models.JSONField(default=list)

    def __str__(self):
        return self.username

    

from django.urls import path
from . import views
from . import recommendations

urlpatterns = [
    path("", views.index, name="index"),
    path('register/', views.register_user, name='register_user'),
    path('login/', views.login_user, name='login_user'),
    path('detect-emotion/', views.detect_emotion, name='detect_emotion'),
    path("get_songs", recommendations.recommend_music, name='get_recommendations'),
    path('spotify_auth/', recommendations.spotify_auth, name='spotify_auth'),
    path('spotify_callback', recommendations.spotify_callback, name='spotify_callback'),
]

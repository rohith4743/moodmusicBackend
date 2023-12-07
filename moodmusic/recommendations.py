import datetime
import requests
from decouple import config
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import redirect
import base64
from .models import SpotifyAccessToken, SpotifyToken
import random
import traceback; 

MOOD_TO_ATTRIBUTES = {
    "SAD": {"target_valence": 0.2, "target_energy": 0.3, "target_tempo": 60},
    "CONFUSED": {"target_valence": 0.3, "target_energy": 0.4, "target_danceability": 0.4},
    "DISGUSTED": {"target_valence": 0.2, "target_energy": 0.6, "target_tempo": 100},
    "ANGRY": {"target_valence": 0.2, "target_energy": 0.8, "target_tempo": 120},
    "SURPRISED": {"target_valence": 0.7, "target_energy": 0.7, "target_danceability": 0.6},
    "FEAR": {"target_valence": 0.3, "target_energy": 0.4, "target_tempo": 80},
    "CALM": {"target_valence": 0.5, "target_energy": 0.2, "target_tempo": 70},
    "HAPPY": {"target_valence": 0.9, "target_energy": 0.8, "target_danceability": 0.7}
}

MOOD_TO_GENRES = {
    "SAD": ["acoustic", "piano", "sad", "soul", "blues", "slow", "ballad", "soft-rock"],
    "CONFUSED": ["indie", "alternative", "experimental", "psychedelic", "folk"],
    "DISGUSTED": ["punk", "heavy-metal", "hard-rock", "grunge", "black-metal", "death-metal"],
    "ANGRY": ["metal", "hardcore", "death-metal", "thrash-metal", "industrial", "heavy"],
    "SURPRISED": ["electronic", "edm", "house", "trance", "electropop", "dubstep"],
    "FEAR": ["ambient", "soundtrack", "dark", "drone", "classical", "experimental"],
    "CALM": ["classical", "ambient", "new-age", "soft-jazz", "easy-listening", "chill"],
    "HAPPY": ["pop", "dance", "upbeat", "happy", "reggae", "ska", "funk", "disco"]
}



def get_spotify_recommendations(mood):
    access_token = fetch_spotify_token()
    mood_attributes = MOOD_TO_ATTRIBUTES.get(mood, {})
    if not mood_attributes:
        raise ValueError("Invalid mood")

    # Randomize seed genres
    seed_genres = random.choice(MOOD_TO_GENRES.get(mood, ["pop"]))
    if isinstance(seed_genres, list):
        seed_genres = random.choice(seed_genres)

    headers = {"Authorization": f"Bearer {access_token}"}
    params = {
        "seed_genres": seed_genres,
        "limit": 10,
        **mood_attributes  # Unpack mood-specific attributes
    }

    response = requests.get("https://api.spotify.com/v1/recommendations", headers=headers, params=params)
    if response.status_code != 200:
        raise Exception(f"Error fetching recommendations: {response.status_code} - {response.text}")

    return response.json()

    
def format_response_for_frontend(recommendations, access_token):
    formatted_tracks = []

    for track in recommendations['tracks']:
        track_info = {
            "name": track['name'],
            "artists": ", ".join(artist['name'] for artist in track['artists']),
            "spotify_url": track['external_urls']['spotify'],
            "album_art_url": track['album']['images'][0]['url'] if track['album']['images'] else None,
            "uri": track["uri"],
            "duration" : track["duration_ms"]
        }
        formatted_tracks.append(track_info)

    return {
        "tracks": formatted_tracks,
        "access_token": access_token  # Be cautious with sending tokens to the frontend
    }


@csrf_exempt
def recommend_music(request):
    if request.method == 'GET':
        mood = request.GET.get('mood', None)

        if not mood:
            return HttpResponseBadRequest("Mood is required.")

        try:
            recommendations = get_spotify_recommendations(mood)
            headers = {
                "Access-Control-Allow-Origin" : "*"
            }
            response = format_response_for_frontend(recommendations, get_access_token())
            # print(response)
            return JsonResponse(response, headers = headers)
        except ValueError as e:
            return HttpResponseBadRequest(str(e))
        except Exception as e:
            traceback.print_exc();
            return JsonResponse({'error': str(e)}, status=500)

    return HttpResponseBadRequest("Invalid request method.")


def fetch_spotify_token():
    # Check if a valid token exists in the database
    try:
        token = SpotifyToken.objects.latest('created_at')
        if not token.is_expired:
            return token.access_token
    except SpotifyToken.DoesNotExist:
        pass

    # If not, fetch a new token
    client_id = config('SPOTIFY_CLIENT_ID')
    client_secret = config('SPOTIFY_CLIENT_SECRET')

    auth_header = base64.b64encode((client_id + ':' + client_secret).encode('ascii')).decode('ascii')
    headers = {'Authorization': f'Basic {auth_header}'}
    data = {'grant_type': 'client_credentials'}

    response = requests.post('https://accounts.spotify.com/api/token', headers=headers, data=data)
    
    if response.status_code == 200:
        token_data = response.json()
        new_token = SpotifyToken.objects.create(
            access_token=token_data['access_token'],
            expires_in=token_data['expires_in']
        )
        return new_token.access_token
    else:
        raise Exception("Failed to retrieve Spotify access token")
    
    
@csrf_exempt
def spotify_auth(request):
    # Redirect to Spotify authorization URL
    auth_url = "https://accounts.spotify.com/authorize?client_id={}&response_type=code&redirect_uri={}&scope={}".format(
        config('SPOTIFY_CLIENT_ID'), config('SPOTIFY_REDIRECT_URI'), 'streaming user-read-playback-state user-read-private user-read-email')
    return redirect(auth_url)

@csrf_exempt
def spotify_callback(request):
    code = request.GET.get('code')
    token_url = 'https://accounts.spotify.com/api/token'
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config('SPOTIFY_REDIRECT_URI'),
        'client_id': config('SPOTIFY_CLIENT_ID'),
        'client_secret': config('SPOTIFY_CLIENT_SECRET'),
    }
    response = requests.post(token_url, data=payload)
    data = response.json()
    expiry = datetime.datetime.now() + datetime.timedelta(seconds=data['expires_in'])
    # Save the token in the database
    SpotifyAccessToken.objects.create(access_token=data['access_token'], refresh_token=data['refresh_token'], expiry=expiry)
    # Redirect to a success page or the application main page
    return redirect('https://moodmusic-frontend.vercel.app')

def get_access_token():
    # Assume there is only one token in the database for simplicity
    token = SpotifyAccessToken.objects.last()
    if not token:
        return JsonResponse({'error': 'No token available'}, status=404)

    if token.expiry <= datetime.datetime.now(datetime.timezone.utc):
        # Token has expired, refresh it
        refresh_url = 'https://accounts.spotify.com/api/token'
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
            'client_id': config('SPOTIFY_CLIENT_ID'),
        }
        # print(data)
        auth_header = base64.b64encode((config('SPOTIFY_CLIENT_ID') + ':' + config('SPOTIFY_CLIENT_SECRET')).encode('ascii')).decode('ascii')
        headers = {'Authorization': f'Basic {auth_header}', 'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post(refresh_url, data=data, headers=headers)
        response_data = response.json()

        # Update the token in the database
        token.access_token = response_data['access_token']
        if "refresh_token" in response_data:
            token.refresh_token = response_data["refresh_token"]
        token.expiry = datetime.datetime.now() + datetime.timedelta(seconds=response_data['expires_in'])
        token.save()

    # Return the valid access token
    return token.access_token

def access_token(request):
    access_token = get_access_token()
    return JsonResponse({"access_token" : access_token})

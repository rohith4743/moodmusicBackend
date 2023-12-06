from django.shortcuts import render
from django.http import HttpResponse
from .models import MusicUser
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import boto3
from decouple import config

# Create your views here.
def index(request):
    return HttpResponse("hello to mood music, tell us your mood, we would recommend you music..")

@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        
        if MusicUser.objects.filter(username=username).count() > 0:
            return JsonResponse({"error" : "A user with this username/email already exists" }, status=400)
        
        if MusicUser.objects.filter(email=data['email']).count() > 0:
            return JsonResponse({"error" : "A user with this username/email already exists" }, status=400)
        
        
        user = MusicUser.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        return JsonResponse({'id': user.id}, status = 201)

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        print(data)
        user = authenticate(
            username=data['username'],
            password=data['password']
        )
        if user is not None:
            login(request, user)
            return JsonResponse({'id': user.id},status=200)
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=400)
    
@csrf_exempt  
def detect_emotion(request):
    if request.method == 'POST':
        # Assuming the image is sent as a file in the request
        image_file = request.FILES.get('image')
        
        if not image_file:
            return JsonResponse({'error': 'No image provided'}, status=400)

        client = boto3.client('rekognition',
                              aws_access_key_id=config('AWS_ACCESS_KEY_ID'),
                              aws_secret_access_key=config('AWS_SECRET_ACCESS_KEY'),
                              region_name=config('AWS_REGION'))

        response = client.detect_faces(
            Image={'Bytes': image_file.read()},
            Attributes=['ALL']
        )

        # Extract emotions from the response
        emotions = response['FaceDetails'][0]['Emotions']
        # Sort by confidence and get the highest one
        top_emotion = max(emotions, key=lambda e: e['Confidence'])

        return JsonResponse({'emotion': top_emotion['Type']})

    return JsonResponse({'error': 'Invalid request'}, status=400)
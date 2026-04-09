import secrets
import os
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import make_password, check_password
from dotenv import load_dotenv

load_dotenv()

# In-memory база данных
fake_users_db = {}

@api_view(['POST'])
def register(request):
    """Регистрация пользователя"""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response(
            {"error": "Username and password required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if username in fake_users_db:
        return Response(
            {"error": "Username already exists"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Хешируем пароль
    hashed_password = make_password(password)
    fake_users_db[username] = {
        'username': username,
        'password': hashed_password
    }
    
    return Response(
        {"message": "User registered successfully"},
        status=status.HTTP_201_CREATED
    )

@api_view(['POST'])
def login(request):
    """Аутентификация пользователя"""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response(
            {"error": "Username and password required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = fake_users_db.get(username)
    
    if not user:
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    # Защита от тайминг-атак
    if not secrets.compare_digest(username, user['username']):
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    if not check_password(password, user['password']):
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    return Response(
        {"message": f"Welcome, {username}!"},
        status=status.HTTP_200_OK
    )
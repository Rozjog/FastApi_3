from functools import wraps
from django.http import JsonResponse
import secrets
import os
from dotenv import load_dotenv

load_dotenv()

MODE = os.getenv('MODE', 'DEV')
DOCS_USER = os.getenv('DOCS_USER', 'admin')
DOCS_PASSWORD = os.getenv('DOCS_PASSWORD', 'secret')

def docs_auth_required(view_func):
    """Декоратор для защиты документации базовой аутентификацией"""
    
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # PROD режим: документация недоступна
        if MODE != 'DEV':
            return JsonResponse(
                {'error': 'Not Found'},
                status=404
            )
        
        # Проверяем заголовок Authorization
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Basic '):
            return JsonResponse(
                {'error': 'Unauthorized'},
                status=401,
                headers={'WWW-Authenticate': 'Basic'}
            )
        
        # Декодируем credentials
        import base64
        encoded = auth_header[6:]
        decoded = base64.b64decode(encoded).decode('utf-8')
        username, password = decoded.split(':', 1)
        
        # Защита от тайминг-атак
        if not (secrets.compare_digest(username, DOCS_USER) and 
                secrets.compare_digest(password, DOCS_PASSWORD)):
            return JsonResponse(
                {'error': 'Unauthorized'},
                status=401,
                headers={'WWW-Authenticate': 'Basic'}
            )
        
        return view_func(request, *args, **kwargs)
    
    return wrapper
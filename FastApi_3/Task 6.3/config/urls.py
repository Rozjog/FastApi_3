from django.contrib import admin
from django.urls import path, re_path
from django.http import JsonResponse, HttpResponseNotFound
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from api.views import register, login
from api.decorators import docs_auth_required
import os
from dotenv import load_dotenv

load_dotenv()

MODE = os.getenv('MODE', 'DEV')

# Настройка Swagger документации
schema_view = get_schema_view(
    openapi.Info(
        title="Task 6.3 API",
        default_version='v1',
        description="API документация для задания 6.3",
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

def not_found_view(request):
    return HttpResponseNotFound()

if MODE == 'DEV':
    # DEV режим: документация защищена аутентификацией
    swagger_view = docs_auth_required(schema_view.with_ui('swagger', cache_timeout=0))
    redoc_view = docs_auth_required(schema_view.with_ui('redoc', cache_timeout=0))
    json_view = docs_auth_required(schema_view.without_ui(cache_timeout=0))
    
    urlpatterns = [
        path('admin/', admin.site.urls),
        path('api/register', register, name='register'),
        path('api/login', login, name='login'),
        path('swagger/', swagger_view, name='swagger-ui'),
        path('redoc/', redoc_view, name='redoc'),
        re_path(r'^swagger(?P<format>\.json|\.yaml)$', json_view, name='schema-json'),
    ]
else:
    # PROD режим: документация отключена
    urlpatterns = [
        path('admin/', not_found_view),
        path('api/register', register, name='register'),
        path('api/login', login, name='login'),
        path('swagger/', not_found_view),
        path('redoc/', not_found_view),
        re_path(r'^swagger(?P<format>\.json|\.yaml)$', not_found_view),
    ]
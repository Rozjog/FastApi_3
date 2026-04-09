import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key-change-me")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ProtectedResponse(BaseModel):
    message: str
    user: str


fake_users_db = {}

# ========== JWT функции ==========
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt

def verify_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_access_token(token)
    
    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    
    user = fake_users_db.get(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    
    return user

def hash_password(password: str) -> str:

    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:

    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str) -> Optional[dict]:

    user = fake_users_db.get(username)
    
    if not user:
        return None

    if not secrets.compare_digest(username, user["username"]):
        return None

    if not verify_password(password, user["hashed_password"]):
        return None
    
    return user

@app.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")  
def register(request: Request, user_data: UserRegister):
    if user_data.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    
    if len(user_data.username) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters"
        )
    
    if len(user_data.password) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 3 characters"
        )
    
    # Хеширование пароля и сохранение
    hashed_password = hash_password(user_data.password)
    
    fake_users_db[user_data.username] = {
        "username": user_data.username,
        "hashed_password": hashed_password
    }
    
    return {"message": "New user created"}

@app.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")  # 5 запросов в минуту
def login(request: Request, user_data: UserLogin):

    if user_data.username not in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    

    user = authenticate_user(user_data.username, user_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed"
        )
    

    access_token = create_access_token(data={"sub": user["username"]})
    
    return TokenResponse(access_token=access_token)

@app.get("/protected_resource", response_model=ProtectedResponse)
def protected_resource(current_user: dict = Depends(get_current_user)):

    return ProtectedResponse(
        message="Access granted",
        user=current_user["username"]
    )

@app.get("/")
def root():
    return {
        "message": "JWT Auth API with Rate Limiting",
        "endpoints": {
            "POST /register": "Create new user (1 per minute)",
            "POST /login": "Get JWT token (5 per minute)",
            "GET /protected_resource": "Access protected resource (requires Bearer token)"
        }
    }

@app.get("/users")
def list_users():
    """Отладочный эндпоинт — показывает список пользователей (только для разработки)"""
    return {
        "users": list(fake_users_db.keys()),
        "count": len(fake_users_db)
    }
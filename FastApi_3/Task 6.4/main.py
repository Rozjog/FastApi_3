import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# ========== Конфигурация ==========
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key-change-me")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ProtectedResponse(BaseModel):
    message: str
    user: str

fake_users_db = {
    "john_doe": {
        "username": "john_doe",
        "hashed_password": pwd_context.hash("securepassword123"),
    },
    "alice": {
        "username": "alice",
        "hashed_password": pwd_context.hash("qwerty123"),
    },
}

# ========== Заглушка authenticate_user ==========
def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = fake_users_db.get(username)
    
    if not user:
        return None
    
    if not pwd_context.verify(password, user["hashed_password"]):
        return None
    
    return user

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

@app.post("/login", response_model=TokenResponse)
def login(user_data: UserLogin):

    user = authenticate_user(user_data.username, user_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
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
    return {"message": "Welcome to JWT Auth API. Use POST /login to get token, then GET /protected_resource with Bearer token"}
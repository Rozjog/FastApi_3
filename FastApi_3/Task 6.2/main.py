import secrets
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.status import HTTP_401_UNAUTHORIZED
from passlib.context import CryptContext
from models import User, UserInDB

app = FastAPI()

# Настройка HTTP Basic Auth
security = HTTPBasic()

# Настройка хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"])

# In-memory база данных
fake_users_db = {}

def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password = credentials.password
    
    user = fake_users_db.get(username)
    
    if user is None:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if not secrets.compare_digest(username, user.username):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return user

from fastapi import status  # добавим в импорты

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    # Проверяем, существует ли пользователь
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Хешируем пароль
    hashed_password = pwd_context.hash(user.password)[:72]
    
    # Создаем объект для хранения в БД
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password
    )
    
    # Сохраняем в in-memory базу
    fake_users_db[user.username] = user_in_db
    
    # Возвращаем сообщение об успехе
    return {"message": "User registered successfully"}

@app.get("/login")
def login(user: UserInDB = Depends(auth_user)):
    return {"message": f"Welcome, {user.username}!"}
from fastapi import FastAPI, HTTPException, status
from database import get_db_connection, init_db
from models import UserCreate, MessageResponse

app = FastAPI()

@app.on_event("startup")
def startup():
    init_db()

@app.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (user.username, user.password)
        )
    
    return MessageResponse(message="User registered successfully!")
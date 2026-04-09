from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.status import HTTP_401_UNAUTHORIZED

app = FastAPI()
security = HTTPBasic()

users_db = {
    "admin": "admin123",
    "user": "user456"
}

def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    correct_password = users_db.get(credentials.username)
    if correct_password is None or credentials.password != correct_password:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/login")
def login(username: str = Depends(auth_user)):
    return {"message": f"You got my secret, welcome"}
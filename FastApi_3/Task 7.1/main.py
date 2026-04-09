from fastapi import FastAPI, Depends, HTTPException, status
from models import UserRegister, UserLogin, TokenResponse, MessageResponse, UserRole
from database import fake_users_db, init_users
from auth import (
    hash_password, create_access_token, authenticate_user,
    get_current_user, require_roles
)

app = FastAPI(title="RBAC API")

init_users()

@app.post("/register", status_code=status.HTTP_201_CREATED, response_model=MessageResponse)
def register(user: UserRegister):
    if user.username in fake_users_db:
        raise HTTPException(status_code=409, detail="User already exists")
    
    fake_users_db[user.username] = {
        "username": user.username,
        "hashed_password": hash_password(user.password),
        "role": user.role
    }
    return MessageResponse(message=f"User {user.username} created with role {user.role.value}")

@app.post("/login", response_model=TokenResponse)
def login(user: UserLogin):
    if user.username not in fake_users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_user = authenticate_user(user.username, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Authorization failed")
    
    token = create_access_token(data={"sub": db_user["username"], "role": db_user["role"].value})
    return TokenResponse(access_token=token)

@app.get("/public", response_model=MessageResponse)
def public():
    return MessageResponse(message="Public endpoint - anyone can access")

@app.get("/protected_resource", response_model=MessageResponse)
def protected_resource(current_user: dict = Depends(require_roles([UserRole.ADMIN, UserRole.USER]))):
    return MessageResponse(message=f"Access granted to {current_user['username']} (role: {current_user['role']})")

@app.post("/admin-only", response_model=MessageResponse)
def admin_only(current_user: dict = Depends(require_roles([UserRole.ADMIN]))):
    return MessageResponse(message=f"Admin {current_user['username']} created a resource")

@app.put("/user-only", response_model=MessageResponse)
def user_only(current_user: dict = Depends(require_roles([UserRole.USER]))):
    return MessageResponse(message=f"User {current_user['username']} updated a resource")

@app.get("/guest-read", response_model=MessageResponse)
def guest_read(current_user: dict = Depends(require_roles([UserRole.GUEST, UserRole.USER, UserRole.ADMIN]))):
    return MessageResponse(message=f"Read access granted to {current_user['username']}")

@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"], "role": current_user["role"]}
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class MessageResponse(BaseModel):
    message: str
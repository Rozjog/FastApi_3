from models import UserRole

# Пользователи: username -> {username, hashed_password, role}
fake_users_db = {}

# Инициализация тестовых пользователей (для демонстрации)
def init_users():
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    if "admin" not in fake_users_db:
        fake_users_db["admin"] = {
            "username": "admin",
            "hashed_password": pwd_context.hash("admin123"),
            "role": UserRole.ADMIN
        }
    
    if "user" not in fake_users_db:
        fake_users_db["user"] = {
            "username": "user",
            "hashed_password": pwd_context.hash("user123"),
            "role": UserRole.USER
        }
    
    if "guest" not in fake_users_db:
        fake_users_db["guest"] = {
            "username": "guest",
            "hashed_password": pwd_context.hash("guest123"),
            "role": UserRole.GUEST
        }
## Общие требования к запуску

Для каждого задания установите зависимости из его `requirements.txt`:

pip install -r requirements.txt

## Запуск приложения

uvicorn main:app --reload

## 6.1

curl -u admin:secret123 http://localhost:8000/login

## 6.2

curl -X POST http://localhost:8000/register -H "Content-Type: application/json" -d "{\"username\": \"alice\", \"password\": \"qwerty123\"}"

## 6.3

curl -u admin:secret123 http://localhost:8000/docs

## 6.4

curl -X POST http://localhost:8000/login -H "Content-Type: application/json" -d "{\"username\": \"john_doe\", \"password\": \"password123\"}"

## 6.5

curl -X POST http://localhost:8000/register -H "Content-Type: application/json" -d "{\"username\": \"alice\", \"password\": \"qwerty123\"}"

curl -X POST http://localhost:8000/login -H "Content-Type: application/json" -d "{\"username\": \"alice\", \"password\": \"qwerty123\"}"

## 7.1

curl -X POST http://localhost:8000/login -H "Content-Type: application/json" -d "{"username":"admin","password":"admin123"}"

curl -X POST http://localhost:8000/login -H "Content-Type: application/json" -d "{"username":"user","password":"user123"}"

curl -X POST http://localhost:8000/login -H "Content-Type: application/json" -d "{"username":"guest","password":"guest123"}"

## 8.1

url -X POST http://127.0.0.1:8000/register -H "Content-Type: application/json" -d "{\"username\": \"test_user\", \"password\": \"12345\"}"


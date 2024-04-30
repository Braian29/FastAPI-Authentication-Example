from fastapi import FastAPI, Depends, HTTPException, Form, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.requests import Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import sqlite3
import secrets
import hashlib
import jwt
import re
from datetime import datetime, timedelta

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# Esquema de autenticación
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scheme_name="Bearer"
)

# Configuración de la base de datos
DATABASE_URL = "database.db"
conn = sqlite3.connect(DATABASE_URL)
cursor = conn.cursor()


# Modelo de usuario
class User(BaseModel):
    id: int
    username: str
    password: str
    email: str

# Modelo de token de acceso
class AccessToken(BaseModel):
    access_token: str
    token_type: str

# Modelo de token de refresh
class RefreshToken(BaseModel):
    refresh_token: str

class CookieOAuth2PasswordBearer(OAuth2PasswordBearer):
    def __init__(self, tokenUrl: str, scheme_name: str = "cookie"):
        super().__init__(tokenUrl=tokenUrl, scheme_name=scheme_name)
        self.scheme_name = scheme_name

    async def __call__(self, request: Request) -> Optional[str]:
        cookie = request.cookies.get("access_token")
        if cookie:
            return cookie
        return None

# Función para hashear contraseñas
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed_password = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"{salt}${hashed_password.hex()}"

# Función para verificar contraseñas
def verify_password(password: str, hashed_password: str) -> bool:
    salt, hashed_password = hashed_password.split("$")
    hashed_input_password = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return hashed_input_password.hex() == hashed_password

# Función para generar tokens de acceso y refresh
def generate_tokens(user: User) -> tuple[AccessToken, RefreshToken]:
    access_token = jwt.encode({"user_id": user.id, "exp": datetime.utcnow() + timedelta(minutes=30)}, "secret_key", algorithm="HS256")
    refresh_token = jwt.encode({"user_id": user.id, "exp": datetime.utcnow() + timedelta(days=30)}, "secret_key", algorithm="HS256")
    cursor.execute("INSERT INTO sessions (user_id, access_token, refresh_token, expires_at) VALUES (?,?,?,?)", (user.id, access_token, refresh_token, datetime.utcnow() + timedelta(minutes=30)))
    conn.commit()
    return AccessToken(access_token=access_token, token_type="bearer"), RefreshToken(refresh_token=refresh_token)

# Función para obtener usuario por token de acceso
def get_user_from_token(token: str) -> Optional[User]:
    try:
        payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
        user_id = payload["user_id"]
        cursor.execute("SELECT * FROM sessions WHERE user_id =? AND access_token =?", (user_id, token))
        session = cursor.fetchone()
        if session:
            cursor.execute("SELECT * FROM users WHERE id =?", (user_id,))
            user = cursor.fetchone()
            return User(**dict(zip([c[0] for c in cursor.description], user)))
        else:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def invalidate_session(request: Request, token: str):
    cursor.execute("DELETE FROM sessions WHERE access_token =?", (token,))
    conn.commit()
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response

# Ruta para inicio de sesión
@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    cursor.execute("SELECT * FROM users WHERE username =?", (username,))
    user = cursor.fetchone()
    if user:
        user = User(**dict(zip([c[0] for c in cursor.description], user)))
        if verify_password(password, user.password):
            invalidate_session(request, request.cookies.get("access_token"))  # Invalidar sesión anterior
            access_token, refresh_token = generate_tokens(user)
            response = RedirectResponse(url="/profile", status_code=302)
            response.set_cookie("access_token", access_token.access_token, secure=True, httponly=True)
            return response
    raise HTTPException(status_code=401, detail="Invalid username or password")

# Ruta para registrarse
@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register_post(username: str = Form(...), password: str = Form(...), email: str = Form(...)):
    if not username or not password or not email:
        raise HTTPException(status_code=400, detail="Invalid input")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_regex, email):
        raise HTTPException(status_code=400, detail="Invalid email")
    cursor.execute("SELECT * FROM users WHERE username =?", (username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = hash_password(password)
    cursor.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)", (username, hashed_password, email))
    conn.commit()
    response = RedirectResponse(url="/login", status_code=302)
    return response


# Ruta para perfil de usuario
@app.get("/profile")
async def profile(request: Request):
    access_token = request.cookies.get("access_token")
    if access_token:
        user = get_user_from_token(access_token)
        if user:
            return templates.TemplateResponse("profile.html", {"request": request, "user": user})
        else:
            raise HTTPException(status_code=401, detail="Invalid token")
    else:
        raise HTTPException(status_code=401, detail="Not authenticated")

# Ruta para obtener token de acceso
@app.post("/token")
async def token_post(username: str, password: str):
    cursor.execute("SELECT * FROM users WHERE username =?", (username,))
    user = cursor.fetchone()
    if user:
        user = User(**dict(zip([c[0] for c in cursor.description], user)))
        if verify_password(password, user.password):
            access_token, refresh_token = generate_tokens(user)
            return {"access_token": access_token.access_token, "token_type": access_token.token_type, "refresh_token": refresh_token.refresh_token}
    raise HTTPException(status_code=401, detail="Invalid username or password")

# Ruta para refrescar token de acceso
@app.post("/refresh")
async def refresh_post(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, "secret_key", algorithms=["HS256"])
        user_id = payload["user_id"]
        cursor.execute("SELECT * FROM users WHERE id =?", (user_id,))
        user = cursor.fetchone()
        user = User(**dict(zip([c[0] for c in cursor.description], user)))
        access_token, refresh_token = generate_tokens(user)
        return {"access_token": access_token.access_token, "token_type": access_token.token_type, "refresh_token": refresh_token.refresh_token}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
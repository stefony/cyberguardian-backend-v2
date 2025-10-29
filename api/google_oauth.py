# api/google_oauth.py
from fastapi import APIRouter, HTTPException, Request
from urllib.parse import urlencode
import os, requests, time

router = APIRouter()

GOOGLE_AUTH_BASE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Използваме readonly обхват (безопасно)
DEFAULT_SCOPES = os.getenv(
    "GOOGLE_SCOPES",
    "https://www.googleapis.com/auth/gmail.readonly"
)

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "")

def _check_env():
    if not (CLIENT_ID and CLIENT_SECRET and REDIRECT_URI):
        raise HTTPException(status_code=500, detail="OAuth env vars are missing")

@router.get("/auth/google/login")
async def google_login(request: Request):
    """
    Генерира OAuth2 URL и пренасочва потребителя към Google.
    """
    _check_env()
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": DEFAULT_SCOPES,
        "access_type": "offline",
        "prompt": "consent",  # за да получим refresh_token
        "include_granted_scopes": "true",
    }
    url = f"{GOOGLE_AUTH_BASE}?{urlencode(params)}"
    return {"auth_url": url}

@router.get("/auth/google/callback")
async def google_callback(request: Request, code: str = "", error: str = ""):
    """
    Получава ?code=... от Google и обменя за access/refresh token.
    (Връща JSON за тест; по-късно ще го запазим в DB/сесия.)
    """
    _check_env()
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Missing 'code'")

    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    resp = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=20)
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {resp.text}")

    tokens = resp.json()
    # За сега – връщаме токените обратно (само за тест). После ще ги пазим сигурно.
    return {
        "received_at": int(time.time()),
        "tokens": {
            "access_token": tokens.get("access_token", ""),
            "expires_in": tokens.get("expires_in", 0),
            "refresh_token": tokens.get("refresh_token", ""),
            "scope": tokens.get("scope", ""),
            "token_type": tokens.get("token_type", ""),
        }
    }

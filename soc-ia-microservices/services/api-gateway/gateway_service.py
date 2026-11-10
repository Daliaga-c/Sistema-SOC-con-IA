from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from pydantic import BaseModel

app = FastAPI(
    title="SOC-IA API Gateway",
    description="Puerta de enlace perimetral y orquestadora de los microservicios del Centro de Operaciones de Seguridad",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# URLs de los microservicios internos
INGESTION_URL = os.getenv("INGESTION_SERVICE_URL", "http://ingestion-service:8001")
ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")
ALERTS_URL = os.getenv("ALERTS_SERVICE_URL", "http://alerts-incidents-service:8003")
COPILOT_URL = os.getenv("COPILOT_SERVICE_URL", "http://genai-copilot-service:8004")
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "http://threat-intelligence-service:8005")

JWT_SECRET = os.getenv("JWT_SECRET", "soc-ia-dev-secret-change-me-very-secure")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "8"))
VALID_MFA_CODES = {"482910", "123456"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DEMO_USERS = {
    "analista.soc@empresa.com": {
        "name": "Diego Aliaga",
        "role": "Analista N1",
        "password_hash": pwd_context.hash("soc-ia-2025"),
    },
    "admin.soc@empresa.com": {
        "name": "Administrador SOC",
        "role": "Admin",
        "password_hash": pwd_context.hash("admin-soc-2025"),
    },
}


class LoginRequest(BaseModel):
    email: str
    password: str
    otp: Optional[str] = None


# Montaje de archivos estáticos y hojas de estilo de la consola del analista
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "analyst-console"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    css_dir = FRONTEND_DIR / "css"
    if css_dir.exists():
        app.mount("/css", StaticFiles(directory=str(css_dir)), name="css")


def get_user_record(email: str) -> Optional[Dict[str, Any]]:
    if not email:
        return None
    return DEMO_USERS.get(email.strip().lower())


def normalize_otp(raw_otp: Optional[str]) -> str:
    if raw_otp is None:
        return ""
    return raw_otp.strip().replace(" ", "")


def create_access_token(email: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=JWT_TTL_HOURS)
    payload = {
        "sub": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expirado") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Token inválido") from exc

    if not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Token sin sujeto válido")
    return payload


async def get_current_user(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Falta cabecera Authorization: Bearer <token>")

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token vacío")

    payload = decode_access_token(token)
    user = get_user_record(payload.get("sub", ""))
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no autorizado o no encontrado")

    return {
        "email": payload["sub"],
        "role": payload.get("role", user["role"]),
        "name": user["name"],
    }


@app.get("/")
async def root():
    dashboard_path = FRONTEND_DIR / "analyst_dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))
    return {"message": "SOC-IA API Gateway activo y operando", "docs": "/docs"}


@app.get("/login")
async def login_page():
    login_path = FRONTEND_DIR / "analyst_login.html"
    if login_path.exists():
        return FileResponse(str(login_path))
    return {"message": "Login page not found"}


@app.post("/auth/login")
@app.post("/api/auth/login")
async def login(payload: LoginRequest):
    email = payload.email.strip().lower()
    user = get_user_record(email)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    if not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    otp_code = normalize_otp(payload.otp)
    if not otp_code or otp_code not in VALID_MFA_CODES:
        raise HTTPException(status_code=401, detail="Código MFA inválido o faltante")

    token = create_access_token(email, user["role"])
    return {
        "message": "Autenticación correcta",
        "token": token,
        "token_type": "bearer",
        "expires_in_hours": JWT_TTL_HOURS,
        "user": {"email": email, "name": user["name"], "role": user["role"]},
    }


@app.get("/auth/me")
async def auth_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {"user": current_user}


@app.get("/health")
async def health_check():
    return {
        "gateway": "UP",
        "services": {
            "ingestion": INGESTION_URL,
            "ml_anomaly": ML_SERVICE_URL,
            "alerts": ALERTS_URL,
            "copilot": COPILOT_URL,
            "threat_intel": THREAT_INTEL_URL,
        },
    }


# Proxy hacia microservicio de Alertas e Incidentes
@app.get("/api/alerts")
async def get_alerts(current_user: Dict[str, Any] = Depends(get_current_user)):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.get(f"{ALERTS_URL}/alerts")
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(status_code=503, content={"error": "Alerts service unavailable", "details": str(exc)})


@app.get("/api/threat-intel/{ip}")
async def get_ip_threat_intelligence(
    ip: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    del current_user
    async with httpx.AsyncClient(timeout=12.0) as client:
        try:
            r = await client.get(f"{THREAT_INTEL_URL}/reputation/{ip}")
            return JSONResponse(status_code=r.status_code, content=r.json())
        except httpx.HTTPError as exc:
            return JSONResponse(
                status_code=503,
                content={"error": "Threat intelligence service unavailable", "details": str(exc)},
            )


@app.post("/api/alerts/{alert_id}/mitigate")
async def mitigate_alert(alert_id: str, request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    body = await request.json()
    body.setdefault("analyst_name", current_user["name"])
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{ALERTS_URL}/alerts/{alert_id}/mitigate", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(status_code=503, content={"error": "Alerts service unavailable", "details": str(exc)})


@app.post("/api/alerts/{alert_id}/feedback")
async def submit_alert_feedback(
    alert_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    body = await request.json()
    body["analyst_name"] = current_user["name"]
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{ALERTS_URL}/alerts/{alert_id}/feedback", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except httpx.HTTPError as exc:
            return JSONResponse(
                status_code=503,
                content={"error": "Alerts service unavailable", "details": str(exc)},
            )


# Proxy hacia microservicio de Inferencia de ML
@app.post("/api/predict")
async def predict_anomaly(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    del current_user
    payload = await request.json()
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{ML_SERVICE_URL}/predict", json=payload)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(status_code=503, content={"error": "ML Service unavailable", "details": str(exc)})


# Proxy hacia microservicio de Asistente IA (Chatbot Copilot)
@app.post("/api/chat")
async def chat_with_copilot(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    del current_user
    payload = await request.json()
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            r = await client.post(f"{COPILOT_URL}/chat", json=payload)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(status_code=503, content={"error": "Copilot Service unavailable", "details": str(exc)})


# Proxy hacia microservicio de Ingesta
@app.post("/api/ingest")
async def ingest_event(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    del current_user
    payload = await request.json()
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{INGESTION_URL}/ingest", json=payload)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(status_code=503, content={"error": "Ingestion service unavailable", "details": str(exc)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("gateway_service:app", host="0.0.0.0", port=8000, reload=True)

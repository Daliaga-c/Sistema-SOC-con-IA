import asyncio
from datetime import datetime, timedelta, timezone
import os
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx
import jwt
from pydantic import BaseModel

app = FastAPI(
    title="SOC-IA API Gateway (Production RBAC, Progressive Copilot & Live Wazuh Stream)",
    description="Puerta de enlace perimetral con autenticación JWT estricta contra PostgreSQL 15, control RBAC y telemetría continua Wazuh",
    version="3.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

INGESTION_URL = os.getenv("INGESTION_SERVICE_URL", "http://ingestion-service:8001")
ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")
ALERTS_URL = os.getenv("ALERTS_SERVICE_URL", "http://alerts-incidents-service:8003")
COPILOT_URL = os.getenv("COPILOT_SERVICE_URL", "http://genai-copilot-service:8004")
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "http://threat-intelligence-service:8005")

JWT_SECRET = os.getenv("JWT_SECRET", "soc-ia-prod-secret-key-2026-nist-compliant")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "8"))


class LoginRequest(BaseModel):
    email: str
    password: str


def create_access_token(user_data: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=JWT_TTL_HOURS)
    payload = {
        "sub": user_data["email"],
        "user_id": user_data.get("id"),
        "name": user_data.get("full_name") or user_data.get("name"),
        "role": user_data["role"],
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=401,
            detail="La sesión ha expirado. Por favor inicia sesión nuevamente.",
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail="Token de autenticación inválido.",
        ) from exc

    if not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Token sin identificador de operador")
    return payload


async def get_current_user(request: Request) -> Dict[str, Any]:
    """Valida estrictamente el token JWT del operador. Sin sesiones anónimas por defecto."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Autenticación obligatoria. Inicia sesión para acceder a la plataforma SOC-IA.",
        )

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token Bearer vacío")

    payload = decode_access_token(token)
    email = payload["sub"]

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{ALERTS_URL}/users/by-email", params={"email": email})
            if r.status_code == 200:
                db_user = r.json()
                if not db_user.get("is_active", True):
                    raise HTTPException(
                        status_code=403,
                        detail="Tu cuenta de usuario ha sido desactivada por un Administrador.",
                    )
                return {
                    "id": db_user.get("id"),
                    "email": db_user["email"],
                    "name": db_user["full_name"],
                    "role": db_user["role"],
                }
            elif r.status_code == 404:
                raise HTTPException(
                    status_code=401,
                    detail="El usuario ya no existe en la base de datos PostgreSQL.",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    return {
        "id": payload.get("user_id"),
        "email": email,
        "name": payload.get("name", email),
        "role": payload.get("role", "ANALISTA_L1"),
    }


def ensure_role(user: Dict[str, Any], allowed_roles: set, action_desc: str) -> None:
    if user.get("role") not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Permiso denegado (RBAC): Tu rol actual '{user.get('role')}' no está autorizado "
                f"para '{action_desc}'. Roles requeridos: {', '.join(sorted(allowed_roles))}."
            ),
        )


# ============================================================================
# AUTENTICACIÓN Y GESTIÓN DE SESIÓN (OBLIGATORIA CONTRA POSTGRESQL)
# ============================================================================

@app.post("/auth/login")
@app.post("/api/auth/login")
async def login(payload: LoginRequest):
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(
                f"{ALERTS_URL}/auth/verify",
                json={"email": payload.email, "password": payload.password},
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Servicio de autenticación y PostgreSQL no disponible: {exc}",
            ) from exc

        if r.status_code != 200:
            err_body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            raise HTTPException(
                status_code=r.status_code,
                detail=err_body.get("detail", "Credenciales inválidas"),
            )

        auth_data = r.json()
        user_record = auth_data["user"]
        token = create_access_token(user_record)
        return {
            "message": "Autenticación verificada en PostgreSQL 15",
            "token": token,
            "token_type": "bearer",
            "expires_in_hours": JWT_TTL_HOURS,
            "user": {
                "id": user_record["id"],
                "email": user_record["email"],
                "name": user_record["full_name"],
                "role": user_record["role"],
                "last_login": user_record.get("last_login"),
            },
        }


@app.get("/auth/me")
@app.get("/api/auth/me")
async def auth_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {"user": current_user}


# ============================================================================
# GESTIÓN DE USUARIOS Y ROLES RBAC EN POSTGRESQL
# ============================================================================

@app.get("/api/users")
async def list_users_proxy(current_user: Dict[str, Any] = Depends(get_current_user)):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{ALERTS_URL}/users")
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/api/users")
async def create_user_proxy(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(current_user, {"ADMIN_SOC"}, "crear nuevos usuarios del SOC")
    body = await request.json()
    body["created_by"] = f"{current_user['name']} ({current_user['email']})"
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{ALERTS_URL}/users", json=body)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.patch("/api/users/{user_id}")
async def update_user_proxy(
    user_id: int,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_role(current_user, {"ADMIN_SOC"}, "modificar roles o estados de usuarios")
    body = await request.json()
    body["updated_by"] = f"{current_user['name']} ({current_user['email']})"
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.patch(f"{ALERTS_URL}/users/{user_id}", json=body)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.delete("/api/users/{user_id}")
async def delete_user_proxy(
    user_id: int, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(current_user, {"ADMIN_SOC"}, "eliminar cuentas de usuario")
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.delete(
            f"{ALERTS_URL}/users/{user_id}",
            params={"deleted_by": f"{current_user['name']} ({current_user['email']})"},
        )
        return JSONResponse(status_code=r.status_code, content=r.json())


# ============================================================================
# SALUD GLOBAL Y TELEMETRÍA EN TIEMPO REAL DE MICROSERVICIOS
# ============================================================================

@app.get("/health")
@app.get("/api/system/health")
async def system_health_check():
    async with httpx.AsyncClient(timeout=5.0) as client:
        async def _fetch(url: str):
            try:
                r = await client.get(url)
                return r.json() if r.status_code == 200 else {"status": "ERROR", "http_code": r.status_code}
            except Exception as e:
                return {"status": "DOWN", "error": str(e)}

        alerts_h, wazuh_h, ml_h, copilot_h, ti_h = await asyncio.gather(
            _fetch(f"{ALERTS_URL}/health"),
            _fetch(f"{INGESTION_URL}/wazuh/status"),
            _fetch(f"{ML_SERVICE_URL}/health"),
            _fetch(f"{COPILOT_URL}/status"),
            _fetch(f"{THREAT_INTEL_URL}/health"),
        )

    return {
        "gateway": "UP",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "postgres": alerts_h,
        "wazuh": wazuh_h,
        "ml_engine": ml_h,
        "copilot_ai": copilot_h,
        "threat_intel": ti_h,
    }


@app.get("/api/metrics")
async def get_metrics_proxy(current_user: Dict[str, Any] = Depends(get_current_user)):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{ALERTS_URL}/metrics")
        return JSONResponse(status_code=r.status_code, content=r.json())


# ============================================================================
# ALERTAS E INCIDENTES (POSTGRESQL 15)
# ============================================================================

@app.get("/api/alerts")
async def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    origin: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    del current_user
    params = {}
    if severity:
        params["severity"] = severity
    if status:
        params["status"] = status
    if origin:
        params["origin"] = origin
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.get(f"{ALERTS_URL}/alerts", params=params)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"error": "Alerts service unavailable", "details": str(exc)},
            )


@app.patch("/api/alerts/{alert_id}/status")
async def update_alert_status_proxy(
    alert_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1"},
        "cambiar estado de alertas",
    )
    body = await request.json()
    body["analyst_name"] = f"{current_user['name']} ({current_user['role']})"
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.patch(f"{ALERTS_URL}/alerts/{alert_id}/status", json=body)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.delete("/api/alerts/{alert_id}")
async def delete_alert_proxy(
    alert_id: str, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(current_user, {"ADMIN_SOC"}, "eliminar alertas de la base de datos")
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.delete(
            f"{ALERTS_URL}/alerts/{alert_id}",
            params={"analyst_name": f"{current_user['name']} ({current_user['role']})"},
        )
        return JSONResponse(status_code=r.status_code, content=r.json())


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
async def mitigate_alert(
    alert_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2"},
        "ejecutar mitigación Active Response en el firewall de Wazuh",
    )
    body = await request.json()
    body["analyst_name"] = f"{current_user['name']} ({current_user['role']})"
    body["analyst_role"] = current_user["role"]
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            r = await client.post(
                f"{ALERTS_URL}/alerts/{alert_id}/mitigate", json=body
            )
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"error": "Alerts service unavailable", "details": str(exc)},
            )


@app.post("/api/alerts/{alert_id}/feedback")
async def feedback_alert(
    alert_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1"},
        "registrar retroalimentación TP/FP para Active Learning",
    )
    body = await request.json()
    body["analyst_name"] = f"{current_user['name']} ({current_user['role']})"
    async with httpx.AsyncClient(timeout=12.0) as client:
        try:
            r = await client.post(
                f"{ALERTS_URL}/alerts/{alert_id}/feedback", json=body
            )
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"error": "Alerts service unavailable", "details": str(exc)},
            )


# ============================================================================
# TELEMETRÍA WAZUH SIEM, TRÁFICO CONTINUO (FP/TN/TP) Y AUDITORÍA
# ============================================================================

@app.get("/api/wazuh/buffer")
async def get_wazuh_buffer(
    limit: int = 100, current_user: Dict[str, Any] = Depends(get_current_user)
):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{ALERTS_URL}/wazuh/buffer", params={"limit": limit})
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/api/wazuh/buffer/{event_id}/escalate")
async def escalate_wazuh_event_proxy(
    event_id: str, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1"},
        "escalar evento de Wazuh a alerta activa",
    )
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(
            f"{ALERTS_URL}/wazuh/buffer/{event_id}/escalate",
            params={"analyst_name": f"{current_user['name']} ({current_user['role']})"},
        )
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.get("/api/wazuh/status")
async def get_wazuh_status_proxy(current_user: Dict[str, Any] = Depends(get_current_user)):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{INGESTION_URL}/wazuh/status")
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/api/wazuh/sync")
async def sync_wazuh_alerts_proxy(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1"},
        "sincronizar alertas reales desde Wazuh Indexer",
    )
    try:
        body = await request.json()
    except Exception:
        body = {"limit": 30, "min_level": 3, "escalate_anomalies": True}
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(f"{INGESTION_URL}/wazuh/sync", json=body)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.get("/api/wazuh/traffic/status")
async def get_wazuh_traffic_status_proxy(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{INGESTION_URL}/wazuh/traffic/status")
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/api/wazuh/traffic/toggle")
async def toggle_wazuh_traffic_proxy(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1"},
        "controlar el generador de tráfico realista hacia Wazuh",
    )
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{INGESTION_URL}/wazuh/traffic/toggle", json=body)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/api/wazuh/traffic/emit")
async def emit_wazuh_traffic_proxy(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1"},
        "emitir lote de tráfico heterogéneo (FP, TN, TP) en Wazuh",
    )
    try:
        body = await request.json()
    except Exception:
        body = {"count": 3, "escalate_to_alerts": True}
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(f"{INGESTION_URL}/wazuh/traffic/emit", json=body)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.get("/api/audit-logs")
async def get_audit_logs_proxy(
    limit: int = 150, current_user: Dict[str, Any] = Depends(get_current_user)
):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{ALERTS_URL}/audit-logs", params={"limit": limit})
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.get("/api/threat-intel/{ip}")
async def get_threat_intel_proxy(
    ip: str, current_user: Dict[str, Any] = Depends(get_current_user)
):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{THREAT_INTEL_URL}/reputation/{ip}")
        return JSONResponse(status_code=r.status_code, content=r.json())


# ============================================================================
# MACHINE LEARNING, ACTIVE LEARNING Y COPILOT IA (GEMINI + OLLAMA)
# ============================================================================

@app.get("/api/ml/active-learning")
async def get_active_learning_proxy(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    del current_user
    async with httpx.AsyncClient(timeout=10.0) as client:
        r_status, r_dataset = await asyncio.gather(
            client.get(f"{ML_SERVICE_URL}/active-learning/status"),
            client.get(f"{ALERTS_URL}/feedback/dataset"),
        )
        status_data = r_status.json() if r_status.status_code == 200 else {}
        dataset_data = r_dataset.json() if r_dataset.status_code == 200 else {"total": 0, "records": []}
        return {
            "active_learning_state": status_data,
            "golden_dataset": dataset_data,
        }


@app.post("/api/ml/retrain")
async def trigger_manual_retrain(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2"},
        "reentrenar el motor de Machine Learning",
    )
    try:
        body = await request.json()
    except Exception:
        body = {}
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(f"{ML_SERVICE_URL}/retrain", json=body)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/api/predict")
async def predict_anomaly(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    del current_user
    payload = await request.json()
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{ML_SERVICE_URL}/predict", json=payload)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/api/predict/log")
async def predict_user_log(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    del current_user
    payload = await request.json()
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(f"{ML_SERVICE_URL}/predict/log", json=payload)
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.get("/api/copilot/status")
async def get_copilot_status_proxy(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    del current_user
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            r = await client.get(f"{COPILOT_URL}/status")
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"status": "OFFLINE", "error": str(exc)},
            )


@app.post("/api/chat")
async def chat_with_copilot(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    payload = await request.json()
    if isinstance(payload, dict):
        payload["analyst_name"] = f"{current_user['name']} ({current_user['role']})"
    async with httpx.AsyncClient(timeout=90.0) as client:
        try:
            r = await client.post(f"{COPILOT_URL}/chat", json=payload)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={
                    "error": True,
                    "detail": f"El microservicio GenAI Copilot (puerto 8004) no responde: {exc}",
                },
            )


@app.post("/api/ingest")
async def ingest_event(
    request: Request, current_user: Dict[str, Any] = Depends(get_current_user)
):
    ensure_role(
        current_user,
        {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1"},
        "ingestar y escalar eventos al SIEM",
    )
    payload = await request.json()
    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.post(f"{INGESTION_URL}/ingest", json=payload)
        return JSONResponse(status_code=r.status_code, content=r.json())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("gateway_service:app", host="0.0.0.0", port=8000, reload=True)

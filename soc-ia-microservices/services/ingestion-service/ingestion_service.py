from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime
import httpx
import os
import uuid
import asyncio
import json
from wazuh_listener import WazuhAlertNormalizer
from wazuh_client import WazuhAPIClient

app = FastAPI(title="SOC-IA Ingestion Service", version="1.0.0")

ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")
ALERTS_URL = os.getenv("ALERTS_SERVICE_URL", "http://alerts-incidents-service:8003")
WAZUH_ALERTS_LOG = os.getenv("WAZUH_ALERTS_LOG", "/var/ossec/logs/alerts/alerts.json")

wazuh_client = WazuhAPIClient()

class RawAuthLog(BaseModel):
    user: str
    ip_origen: str
    resultado: str # SUCCESS, FAILURE, ERROR
    origen: str = "Portal Web Dummy" # Portal Web Dummy, Dataset, SSH, Wazuh
    dispositivo: str = "Desktop Chrome"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

async def process_and_forward(normalized_event: dict):
    # Enviar al servicio de ML para calcular el score de anomalía
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            ml_response = await client.post(f"{ML_SERVICE_URL}/predict", json=normalized_event)
            score_data = ml_response.json() if ml_response.status_code == 200 else {"risk_score": 50.0, "is_anomaly": False}
        except Exception:
            score_data = {"risk_score": 45.0, "is_anomaly": False, "error": "ML offline"}

        # Si el evento es anómalo o fallido, publicar en el servicio de alertas
        if score_data.get("is_anomaly") or normalized_event.get("status") == "FAILURE":
            alert_payload = {
                "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
                "title": f"Actividad sospechosa de login ({normalized_event['source_system']})",
                "severity": "CRÍTICA" if score_data.get("risk_score", 0) >= 80 else ("ALTA" if score_data.get("risk_score", 0) >= 60 else "MEDIA"),
                "raw_event": normalized_event,
                "ml_score": score_data
            }
            try:
                await client.post(f"{ALERTS_URL}/alerts", json=alert_payload)
            except Exception as e:
                print(f"[ERROR] No se pudo enviar alerta: {e}")

async def run_wazuh_background_tail(log_path: str):
    """Monitorea el archivo de alertas de Wazuh en background de forma no bloqueante"""
    print(f"[*] [Auto-Listener] Iniciando escucha en segundo plano para: {log_path}")
    while not os.path.exists(log_path):
        await asyncio.sleep(2.0)

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.5)
                    continue
                try:
                    alert = json.loads(line)
                    normalized = WazuhAlertNormalizer.normalize_to_canonical(alert)
                    if normalized:
                        event_payload = {
                            "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
                            "timestamp": normalized["timestamp"],
                            "source_system": normalized["origen"],
                            "user": normalized["user"],
                            "source_ip": normalized["ip_origen"],
                            "status": normalized["resultado"],
                            "metadata": {
                                "dispositivo": normalized["dispositivo"],
                                "wazuh": normalized.get("wazuh_metadata", {})
                            }
                        }
                        await process_and_forward(event_payload)
                except Exception as e:
                    print(f"[Auto-Listener] Error procesando línea: {e}")
    except Exception as e:
        print(f"[Auto-Listener] Error de acceso a archivo {log_path}: {e}")

ENABLE_WAZUH_AUTO_LISTENER = os.getenv("ENABLE_WAZUH_AUTO_LISTENER", "false").lower() == "true"

@app.on_event("startup")
async def on_startup():
    # Solo se activa si se especifica explícitamente en el .env (por defecto: desactivado)
    if ENABLE_WAZUH_AUTO_LISTENER:
        print(f"[*] Auto-listener habilitado por variable de entorno para: {WAZUH_ALERTS_LOG}")
        asyncio.create_task(run_wazuh_background_tail(WAZUH_ALERTS_LOG))
    else:
        print("[*] Ingestion Service listo. Modo Webhook/API activo (Auto-listener desactivado para mayor control).")

@app.post("/ingest")
async def ingest_log(log: RawAuthLog, background_tasks: BackgroundTasks):
    normalized = {
        "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
        "timestamp": log.timestamp,
        "source_system": log.origen,
        "user": log.user,
        "source_ip": log.ip_origen,
        "status": log.resultado.upper(),
        "metadata": {
            "dispositivo": log.dispositivo
        }
    }
    background_tasks.add_task(process_and_forward, normalized)
    return {"status": "INGESTED", "event_id": normalized["event_id"]}

@app.post("/wazuh/webhook")
async def wazuh_webhook(alert: dict, background_tasks: BackgroundTasks):
    """Endpoint directo para recibir alertas push de Wazuh (integratord)"""
    normalized = WazuhAlertNormalizer.normalize_to_canonical(alert)
    if not normalized:
        return {"status": "IGNORED", "reason": "Alerta filtrada: no corresponde a anomalía de autenticación"}

    event_payload = {
        "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
        "timestamp": normalized["timestamp"],
        "source_system": normalized["origen"],
        "user": normalized["user"],
        "source_ip": normalized["ip_origen"],
        "status": normalized["resultado"],
        "metadata": {
            "dispositivo": normalized["dispositivo"],
            "wazuh": normalized.get("wazuh_metadata", {})
        }
    }
    background_tasks.add_task(process_and_forward, event_payload)
    return {"status": "ACCEPTED", "rule_id": normalized.get("wazuh_metadata", {}).get("rule_id")}

@app.get("/wazuh/status")
async def get_wazuh_status():
    """Prueba la conexión real con la API del Wazuh Manager"""
    try:
        info = await wazuh_client.test_connection()
        return {"status": "CONNECTED", "wazuh_api": info}
    except Exception as e:
        return {"status": "DISCONNECTED", "error": str(e)}

@app.get("/health")
async def health():
    return {"status": "UP", "service": "ingestion-service"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ingestion_service:app", host="0.0.0.0", port=8001, reload=True)

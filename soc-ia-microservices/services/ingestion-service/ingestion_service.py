from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from datetime import datetime
import httpx
import os
import uuid

app = FastAPI(title="SOC-IA Ingestion Service", version="1.0.0")

ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")
ALERTS_URL = os.getenv("ALERTS_SERVICE_URL", "http://alerts-incidents-service:8003")

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
        if score_data.get("is_anomaly") or normalized_event["status"] == "FAILURE":
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

@app.get("/health")
async def health():
    return {"status": "UP", "service": "ingestion-service"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ingestion_service:app", host="0.0.0.0", port=8001, reload=True)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

app = FastAPI(title="SOC-IA Alerts & Incidents Service", version="1.0.0")

# Almacén de alertas en memoria (para persistencia en PostgreSQL o Redis)
ALERTS_DB: Dict[str, dict] = {}

class AlertCreate(BaseModel):
    alert_id: Optional[str] = None
    title: str
    severity: str
    raw_event: Dict[str, Any]
    ml_score: Optional[Dict[str, Any]] = None
    status: str = "NUEVA"
    mitre_attack: List[str] = ["T1110 - Brute Force"]

class MitigationRequest(BaseModel):
    analyst_name: str
    action: str = "BLOCK_IP" # BLOCK_IP, ISOLATE_HOST, RESET_PASSWORD
    target: str # IP o usuario
    approved_by_human: bool = True

class FeedbackRequest(BaseModel):
    analyst_name: str
    feedback: str # VERDADERO_POSITIVO, FALSO_POSITIVO
    notes: Optional[str] = None

# Inicializar con alertas demostrativas del SOC
def seed_demo_alerts():
    demos = [
        {
            "alert_id": "ALT-10023",
            "created_at": datetime.utcnow().isoformat(),
            "title": "Ataque de Fuerza Bruta en Portal Web",
            "severity": "CRÍTICA",
            "status": "NUEVA",
            "raw_event": {
                "source_system": "Portal Web Dummy",
                "user": "admin",
                "source_ip": "185.220.101.5",
                "status": "FAILURE",
                "metadata": {"dispositivo": "Python-urllib/3.9", "intentos": 14}
            },
            "ml_score": {
                "risk_score": 92.5,
                "is_anomaly": True,
                "contributing_features": [
                    {"factor": "14 intentos fallidos en 60 segundos", "impacto": "+45%"},
                    {"factor": "Nodo de salida Tor detectado", "impacto": "+30%"},
                    {"factor": "Usuario crítico 'admin'", "impacto": "+17.5%"}
                ]
            },
            "mitre_attack": ["T1110.001 - Password Guessing", "T1078 - Valid Accounts"],
            "mitigation_status": "PENDIENTE_APROBACION"
        },
        {
            "alert_id": "ALT-10024",
            "created_at": datetime.utcnow().isoformat(),
            "title": "Inicio de Sesión en Horario No Laboral (SSH)",
            "severity": "ALTA",
            "status": "EN_INVESTIGACION",
            "raw_event": {
                "source_system": "SSH",
                "user": "daliaga",
                "source_ip": "190.236.14.82",
                "status": "SUCCESS",
                "metadata": {"puerto": 22, "hora": "03:42 AM"}
            },
            "ml_score": {
                "risk_score": 74.0,
                "is_anomaly": True,
                "contributing_features": [
                    {"factor": "Horario inusual (03:42 AM)", "impacto": "+40%"},
                    {"factor": "IP no registrada previamente para el usuario", "impacto": "+34%"}
                ]
            },
            "mitre_attack": ["T1078.003 - Local Accounts"],
            "mitigation_status": "NINGUNA"
        },
        {
            "alert_id": "ALT-10025",
            "created_at": datetime.utcnow().isoformat(),
            "title": "Autenticación Sospechosa en Lote (Dataset Ingestion)",
            "severity": "MEDIA",
            "status": "NUEVA",
            "raw_event": {
                "source_system": "Dataset",
                "user": "service_account_sync",
                "source_ip": "10.0.4.15",
                "status": "FAILURE",
                "metadata": {"dataset": "CIC-IDS2017"}
            },
            "ml_score": {
                "risk_score": 58.0,
                "is_anomaly": False,
                "contributing_features": [
                    {"factor": "Reintento de sincronización de API interna", "impacto": "+25%"}
                ]
            },
            "mitre_attack": ["T1078 - Valid Accounts"],
            "mitigation_status": "NINGUNA"
        }
    ]
    for d in demos:
        ALERTS_DB[d["alert_id"]] = d

seed_demo_alerts()

@app.get("/alerts")
async def list_alerts(origin: Optional[str] = None, severity: Optional[str] = None):
    results = list(ALERTS_DB.values())
    if origin:
        results = [a for a in results if a["raw_event"].get("source_system") == origin]
    if severity:
        results = [a for a in results if a.get("severity") == severity]
    return {"total": len(results), "alerts": sorted(results, key=lambda x: x["created_at"], reverse=True)}

@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    if alert_id not in ALERTS_DB:
        raise HTTPException(status_code=404, detail="Alert not found")
    return ALERTS_DB[alert_id]

@app.post("/alerts")
async def create_alert(alert: AlertCreate):
    aid = alert.alert_id or f"ALT-{uuid.uuid4().hex[:8].upper()}"
    new_alert = {
        "alert_id": aid,
        "created_at": datetime.utcnow().isoformat(),
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "raw_event": alert.raw_event,
        "ml_score": alert.ml_score or {"risk_score": 50.0, "is_anomaly": False},
        "mitre_attack": alert.mitre_attack,
        "mitigation_status": "PENDIENTE_APROBACION" if alert.severity in ["CRÍTICA", "ALTA"] else "NINGUNA"
    }
    ALERTS_DB[aid] = new_alert
    return {"status": "CREATED", "alert": new_alert}

@app.post("/alerts/{alert_id}/mitigate")
async def execute_mitigation(alert_id: str, req: MitigationRequest):
    if alert_id not in ALERTS_DB:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not req.approved_by_human:
        raise HTTPException(status_code=400, detail="Mitigation requires human-in-the-loop sign-off")
    
    alert = ALERTS_DB[alert_id]
    alert["status"] = "CONTENIDA"
    alert["mitigation_status"] = f"EJECUTADA ({req.action} on {req.target} por {req.analyst_name})"
    
    return {
        "status": "MITIGATED",
        "action": req.action,
        "target": req.target,
        "operator": req.analyst_name,
        "timestamp": datetime.utcnow().isoformat(),
        "command_dispatched": f"wazuh-control active-response {req.action} target={req.target}"
    }

@app.post("/alerts/{alert_id}/feedback")
async def submit_feedback(alert_id: str, req: FeedbackRequest):
    if alert_id not in ALERTS_DB:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = ALERTS_DB[alert_id]
    alert["status"] = "CERRADA_TP" if req.feedback == "VERDADERO_POSITIVO" else "CERRADA_FP"
    alert["feedback"] = {
        "label": req.feedback,
        "analyst": req.analyst_name,
        "notes": req.notes,
        "timestamp": datetime.utcnow().isoformat()
    }
    return {"status": "FEEDBACK_RECORDED", "alert_id": alert_id}

@app.get("/health")
async def health():
    return {"status": "UP", "service": "alerts-incidents-service", "total_alerts": len(ALERTS_DB)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("alerts_incidents_service:app", host="0.0.0.0", port=8003, reload=True)

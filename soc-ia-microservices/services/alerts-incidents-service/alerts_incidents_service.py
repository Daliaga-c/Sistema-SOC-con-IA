from datetime import datetime, timezone
import logging
import os
import uuid
from typing import Any, Dict, List, Literal, Optional

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import AlertRecord, AuditLog, FeedbackRecord, SessionLocal, create_db_and_tables, get_db
from wazuh_client import dispatch_active_response

app = FastAPI(title="SOC-IA Alerts & Incidents Service", version="1.0.0")
logger = logging.getLogger(__name__)
ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")
ACTIVE_LEARNING_TOKEN = os.getenv("ACTIVE_LEARNING_TOKEN", "")
active_learning_scheduler = BackgroundScheduler(timezone="UTC")

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
    feedback: Literal["VERDADERO_POSITIVO", "FALSO_POSITIVO"]
    notes: Optional[str] = None


def retrain_from_feedback() -> None:
    if not ACTIVE_LEARNING_TOKEN:
        logger.error("Active Learning is not configured: ACTIVE_LEARNING_TOKEN is missing")
        return

    with SessionLocal() as db:
        feedback_records = db.query(FeedbackRecord).all()
        samples = [
            {
                "alert_id": record.alert_id,
                "label": record.label,
                "event": record.raw_event,
            }
            for record in feedback_records
        ]

    if not samples:
        logger.info("Skipping Active Learning retraining: no analyst feedback is available")
        return

    try:
        response = httpx.post(
            f"{ML_SERVICE_URL}/retrain",
            headers={"X-Active-Learning-Token": ACTIVE_LEARNING_TOKEN},
            json={"records": samples},
            timeout=120.0,
        )
        response.raise_for_status()
    except httpx.HTTPError:
        logger.exception("Active Learning scheduled retraining failed")
        return

    logger.info("Active Learning retraining completed: %s", response.json())


def _serialize_alert(record: AlertRecord) -> Dict[str, Any]:
    return {
        "alert_id": record.alert_id,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "title": record.title,
        "severity": record.severity,
        "status": record.status,
        "raw_event": record.raw_event,
        "ml_score": record.ml_score,
        "mitre_attack": record.mitre_attack,
        "mitigation_status": record.mitigation_status,
        "feedback": record.feedback,
    }


def migrate_legacy_feedback(db: Session) -> None:
    existing_alert_ids = {
        record.alert_id for record in db.query(FeedbackRecord.alert_id).all()
    }
    legacy_alerts = db.query(AlertRecord).filter(AlertRecord.feedback.isnot(None)).all()

    for alert in legacy_alerts:
        if alert.alert_id in existing_alert_ids:
            continue
        feedback = alert.feedback
        if not isinstance(feedback, dict):
            logger.warning("Skipping malformed legacy feedback for alert %s", alert.alert_id)
            continue

        label = feedback.get("label")
        analyst_name = feedback.get("analyst")
        if (
            label not in ("VERDADERO_POSITIVO", "FALSO_POSITIVO")
            or not isinstance(analyst_name, str)
            or not analyst_name
        ):
            logger.warning("Skipping invalid legacy feedback for alert %s", alert.alert_id)
            continue

        db.add(
            FeedbackRecord(
                alert_id=alert.alert_id,
                label=label,
                analyst_name=analyst_name,
                notes=feedback.get("notes"),
                raw_event=alert.raw_event,
                created_at=alert.created_at,
            )
        )

    db.commit()


def seed_demo_alerts(db: Session):
    if db.query(AlertRecord).count() > 0:
        return

    demos = [
        {
            "alert_id": "ALT-10023",
            "created_at": datetime.utcnow(),
            "title": "Ataque de Fuerza Bruta en Portal Web",
            "severity": "CRÍTICA",
            "status": "NUEVA",
            "raw_event": {
                "source_system": "Portal Web Dummy",
                "user": "admin",
                "source_ip": "185.220.101.5",
                "status": "FAILURE",
                "metadata": {"dispositivo": "Python-urllib/3.9", "intentos": 14},
            },
            "ml_score": {
                "risk_score": 92.5,
                "is_anomaly": True,
                "contributing_features": [
                    {"factor": "14 intentos fallidos en 60 segundos", "impacto": "+45%"},
                    {"factor": "Nodo de salida Tor detectado", "impacto": "+30%"},
                    {"factor": "Usuario crítico 'admin'", "impacto": "+17.5%"},
                ],
            },
            "mitre_attack": ["T1110.001 - Password Guessing", "T1078 - Valid Accounts"],
            "mitigation_status": "PENDIENTE_APROBACION",
        },
        {
            "alert_id": "ALT-10024",
            "created_at": datetime.utcnow(),
            "title": "Inicio de Sesión en Horario No Laboral (SSH)",
            "severity": "ALTA",
            "status": "EN_INVESTIGACION",
            "raw_event": {
                "source_system": "SSH",
                "user": "daliaga",
                "source_ip": "190.236.14.82",
                "status": "SUCCESS",
                "metadata": {"puerto": 22, "hora": "03:42 AM"},
            },
            "ml_score": {
                "risk_score": 74.0,
                "is_anomaly": True,
                "contributing_features": [
                    {"factor": "Horario inusual (03:42 AM)", "impacto": "+40%"},
                    {"factor": "IP no registrada previamente para el usuario", "impacto": "+34%"},
                ],
            },
            "mitre_attack": ["T1078.003 - Local Accounts"],
            "mitigation_status": "NINGUNA",
        },
        {
            "alert_id": "ALT-10025",
            "created_at": datetime.utcnow(),
            "title": "Autenticación Sospechosa en Lote (Dataset Ingestion)",
            "severity": "MEDIA",
            "status": "NUEVA",
            "raw_event": {
                "source_system": "Dataset",
                "user": "service_account_sync",
                "source_ip": "10.0.4.15",
                "status": "FAILURE",
                "metadata": {"dataset": "CIC-IDS2017"},
            },
            "ml_score": {
                "risk_score": 58.0,
                "is_anomaly": False,
                "contributing_features": [
                    {"factor": "Reintento de sincronización de API interna", "impacto": "+25%"}
                ],
            },
            "mitre_attack": ["T1078 - Valid Accounts"],
            "mitigation_status": "NINGUNA",
        },
    ]

    for item in demos:
        db.add(
            AlertRecord(
                alert_id=item["alert_id"],
                created_at=item["created_at"],
                title=item["title"],
                severity=item["severity"],
                status=item["status"],
                raw_event=item["raw_event"],
                ml_score=item["ml_score"],
                mitigation_status=item["mitigation_status"],
                mitre_attack=item["mitre_attack"],
            )
        )

    db.commit()


@app.on_event("startup")
def startup_event():
    create_db_and_tables()
    with SessionLocal() as db:
        migrate_legacy_feedback(db)
        seed_demo_alerts(db)
    if ACTIVE_LEARNING_TOKEN and not active_learning_scheduler.running:
        active_learning_scheduler.add_job(
            retrain_from_feedback,
            "interval",
            weeks=1,
            id="weekly_active_learning_retraining",
            replace_existing=True,
        )
        active_learning_scheduler.start()
    elif not ACTIVE_LEARNING_TOKEN:
        logger.warning("Weekly Active Learning is disabled: set ACTIVE_LEARNING_TOKEN")


@app.on_event("shutdown")
def shutdown_event():
    if active_learning_scheduler.running:
        active_learning_scheduler.shutdown()


@app.get("/alerts")
async def list_alerts(
    origin: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    results = db.query(AlertRecord).all()
    if origin:
        results = [alert for alert in results if alert.raw_event.get("source_system") == origin]
    if severity:
        results = [alert for alert in results if alert.severity == severity]

    alerts = [_serialize_alert(alert) for alert in results]
    return {"total": len(alerts), "alerts": sorted(alerts, key=lambda x: x["created_at"], reverse=True)}


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(AlertRecord).filter(AlertRecord.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize_alert(alert)


@app.post("/alerts")
async def create_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    aid = alert.alert_id or f"ALT-{uuid.uuid4().hex[:8].upper()}"
    new_alert = AlertRecord(
        alert_id=aid,
        created_at=datetime.utcnow(),
        title=alert.title,
        severity=alert.severity,
        status=alert.status,
        raw_event=alert.raw_event,
        ml_score=alert.ml_score or {"risk_score": 50.0, "is_anomaly": False},
        mitre_attack=alert.mitre_attack,
        mitigation_status="PENDIENTE_APROBACION" if alert.severity in ["CRÍTICA", "ALTA"] else "NINGUNA",
    )
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    return {"status": "CREATED", "alert": _serialize_alert(new_alert)}


@app.post("/alerts/{alert_id}/mitigate")
async def execute_mitigation(alert_id: str, req: MitigationRequest, db: Session = Depends(get_db)):
    alert = db.query(AlertRecord).filter(AlertRecord.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not req.approved_by_human:
        raise HTTPException(status_code=400, detail="Mitigation requires human-in-the-loop sign-off")

    alert.status = "CONTENIDA"
    alert.mitigation_status = f"EJECUTADA ({req.action} on {req.target} por {req.analyst_name})"

    wazuh_result = dispatch_active_response(req.action, req.target)

    audit_entry = AuditLog(
        alert_id=alert.alert_id,
        analyst_name=req.analyst_name,
        action=req.action,
        target=req.target,
        approved_by_human=str(req.approved_by_human).lower(),
        details={
            "timestamp": datetime.utcnow().isoformat(),
            "command_dispatched": f"wazuh-control active-response {req.action} target={req.target}",
            "wazuh_result": wazuh_result,
        },
    )
    db.add(audit_entry)
    db.commit()

    return {
        "status": "MITIGATED",
        "action": req.action,
        "target": req.target,
        "operator": req.analyst_name,
        "timestamp": datetime.utcnow().isoformat(),
        "command_dispatched": f"wazuh-control active-response {req.action} target={req.target}",
        "wazuh_result": wazuh_result,
    }


@app.post("/alerts/{alert_id}/feedback")
async def submit_feedback(alert_id: str, req: FeedbackRequest, db: Session = Depends(get_db)):
    alert = db.query(AlertRecord).filter(AlertRecord.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    recorded_at = datetime.now(timezone.utc)
    alert.status = "CERRADA_TP" if req.feedback == "VERDADERO_POSITIVO" else "CERRADA_FP"
    feedback_payload = {
        "label": req.feedback,
        "analyst": req.analyst_name,
        "notes": req.notes,
        "timestamp": recorded_at.isoformat(),
    }
    alert.feedback = feedback_payload

    feedback_record = db.query(FeedbackRecord).filter(FeedbackRecord.alert_id == alert_id).first()
    if feedback_record is None:
        feedback_record = FeedbackRecord(alert_id=alert_id, raw_event=alert.raw_event)
        db.add(feedback_record)
    feedback_record.label = req.feedback
    feedback_record.analyst_name = req.analyst_name
    feedback_record.notes = req.notes
    feedback_record.raw_event = alert.raw_event
    feedback_record.created_at = recorded_at.replace(tzinfo=None)

    db.commit()
    return {"status": "FEEDBACK_RECORDED", "alert_id": alert_id, "feedback": feedback_payload}


@app.get("/health")
async def health(db: Session = Depends(get_db)):
    total_alerts = db.query(AlertRecord).count()
    return {"status": "UP", "service": "alerts-incidents-service", "total_alerts": total_alerts}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("alerts_incidents_service:app", host="0.0.0.0", port=8003, reload=True)

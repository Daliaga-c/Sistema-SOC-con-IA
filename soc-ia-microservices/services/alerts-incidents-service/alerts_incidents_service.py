from datetime import datetime
import os
import uuid
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import (
    AlertRecord,
    AuditLog,
    MLFeedbackRecord,
    SessionLocal,
    UserRecord,
    WazuhEventBuffer,
    create_db_and_tables,
    get_db,
    hash_password,
    verify_password,
    verify_postgres_connection,
)
from wazuh_client import dispatch_active_response

app = FastAPI(
    title="SOC-IA Alerts, Users & Incidents Service (PostgreSQL 15)",
    version="3.0.0",
)

ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")

VALID_ROLES = {"ADMIN_SOC", "ANALISTA_L2", "ANALISTA_L1", "AUDITOR"}
VALID_ALERT_STATUSES = {
    "NUEVA",
    "EN_INVESTIGACION",
    "CONTENIDA",
    "CERRADA_TP",
    "CERRADA_FP",
    "DESCARTADA",
}


class AlertCreate(BaseModel):
    alert_id: Optional[str] = None
    title: str
    severity: str
    raw_event: Dict[str, Any]
    ml_score: Optional[Dict[str, Any]] = None
    status: str = "NUEVA"
    mitre_attack: List[str] = Field(default_factory=lambda: ["T1110 - Brute Force"])


class AlertStatusUpdate(BaseModel):
    status: str
    analyst_name: str
    notes: Optional[str] = None


class WazuhBufferCreate(BaseModel):
    event_id: Optional[str] = None
    rule_id: Optional[str] = "5710"
    rule_level: Optional[int] = 5
    user: str
    source_ip: str
    status: str = "FAILURE"
    source_system: str = "Wazuh SIEM"
    raw_payload: Dict[str, Any]
    ml_evaluation: Optional[Dict[str, Any]] = None
    escalated_to_alert: bool = False


class MitigationRequest(BaseModel):
    analyst_name: str
    analyst_role: Optional[str] = "ANALISTA_L2"
    action: str = "BLOCK_IP"  # BLOCK_IP, ISOLATE_HOST, DISABLE_ACCOUNT
    target: str
    approved_by_human: bool = True


class FeedbackRequest(BaseModel):
    analyst_name: str
    feedback: str  # VERDADERO_POSITIVO, FALSO_POSITIVO
    notes: Optional[str] = None


class AuthVerifyRequest(BaseModel):
    email: str
    password: str


class UserCreateRequest(BaseModel):
    email: str
    full_name: str
    password: str
    role: str = "ANALISTA_L1"
    is_active: bool = True
    created_by: Optional[str] = "ADMIN_SOC"


class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None
    updated_by: Optional[str] = "ADMIN_SOC"


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


def _serialize_user(user: UserRecord) -> Dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "created_by": user.created_by,
    }


def purge_legacy_demo_data(db: Session) -> None:
    """Elimina cualquier dato mock o semilla heredado para garantizar 100% telemetría real."""
    demo_alert_ids = ["ALT-10023", "ALT-10024", "ALT-10025", "ALT-99999"]
    db.query(AlertRecord).filter(AlertRecord.alert_id.in_(demo_alert_ids)).delete(
        synchronize_session=False
    )
    db.query(WazuhEventBuffer).filter(
        WazuhEventBuffer.event_id.in_(["WAZ-TEST-99"])
    ).delete(synchronize_session=False)
    db.query(AuditLog).filter(AuditLog.alert_id.in_(demo_alert_ids)).delete(
        synchronize_session=False
    )
    db.query(MLFeedbackRecord).filter(
        MLFeedbackRecord.alert_id.in_(demo_alert_ids)
    ).delete(synchronize_session=False)
    # También eliminar alertas cuyo source_system sea dummy
    all_alerts = db.query(AlertRecord).all()
    for a in all_alerts:
        src = str((a.raw_event or {}).get("source_system", ""))
        if "Dummy" in src or "Test Portal" in src:
            db.delete(a)
    db.commit()


def ensure_initial_users(db: Session) -> None:
    """Asegura cuentas operativas reales en PostgreSQL (soc_users) para cada rol del SOC."""
    initial_accounts = [
        {
            "email": "admin.soc@empresa.com",
            "full_name": "Administrador General SOC",
            "password": "admin-soc-2025",
            "role": "ADMIN_SOC",
        },
        {
            "email": "analista.soc@empresa.com",
            "full_name": "Diego Aliaga",
            "password": "soc-ia-2025",
            "role": "ANALISTA_L2",
        },
        {
            "email": "triaje.soc@empresa.com",
            "full_name": "Operador Triaje N1",
            "password": "triaje-soc-2025",
            "role": "ANALISTA_L1",
        },
        {
            "email": "auditor.soc@empresa.com",
            "full_name": "Auditor Forense",
            "password": "auditor-soc-2025",
            "role": "AUDITOR",
        },
    ]

    for acc in initial_accounts:
        existing = (
            db.query(UserRecord)
            .filter(UserRecord.email == acc["email"])
            .first()
        )
        if not existing:
            db.add(
                UserRecord(
                    email=acc["email"],
                    full_name=acc["full_name"],
                    password_hash=hash_password(acc["password"]),
                    role=acc["role"],
                    is_active=True,
                    created_at=datetime.utcnow(),
                    created_by="POSTGRES_BOOTSTRAP",
                )
            )
    db.commit()


@app.on_event("startup")
def startup_event():
    create_db_and_tables()
    with SessionLocal() as db:
        purge_legacy_demo_data(db)
        ensure_initial_users(db)


# ============================================================================
# ENDPOINTS DE AUTENTICACIÓN Y GESTIÓN DE USUARIOS / ROLES (RBAC EN POSTGRESQL)
# ============================================================================

@app.post("/auth/verify")
async def verify_user_credentials(req: AuthVerifyRequest, db: Session = Depends(get_db)):
    email_clean = req.email.strip().lower()
    user = db.query(UserRecord).filter(UserRecord.email == email_clean).first()

    if not user or not verify_password(req.password, user.password_hash):
        db.add(
            AuditLog(
                alert_id="AUTH-EVENT",
                analyst_name=email_clean or "anonymous",
                action="AUTH_LOGIN_FAILED",
                target="SOC Console",
                approved_by_human="false",
                details={
                    "timestamp": datetime.utcnow().isoformat(),
                    "reason": "Credenciales inválidas o usuario inexistente",
                },
            )
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")

    if not user.is_active:
        db.add(
            AuditLog(
                alert_id="AUTH-EVENT",
                analyst_name=user.email,
                action="AUTH_LOGIN_BLOCKED",
                target="SOC Console",
                approved_by_human="false",
                details={
                    "timestamp": datetime.utcnow().isoformat(),
                    "reason": "Cuenta desactivada por el administrador",
                },
            )
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="Esta cuenta de usuario se encuentra desactivada. Contacta al Administrador del SOC.",
        )

    user.last_login = datetime.utcnow()
    db.add(
        AuditLog(
            alert_id="AUTH-EVENT",
            analyst_name=f"{user.full_name} ({user.role})",
            action="AUTH_LOGIN_SUCCESS",
            target="SOC Console",
            approved_by_human="true",
            details={
                "timestamp": datetime.utcnow().isoformat(),
                "email": user.email,
                "role": user.role,
            },
        )
    )
    db.commit()
    db.refresh(user)
    return {"status": "AUTHENTICATED", "user": _serialize_user(user)}


@app.get("/users")
async def list_users(db: Session = Depends(get_db)):
    users = db.query(UserRecord).order_by(UserRecord.id.asc()).all()
    return {
        "total": len(users),
        "roles_catalog": [
            {
                "role": "ADMIN_SOC",
                "label": "Administrador del SOC",
                "permissions": [
                    "Gestión total de usuarios y roles",
                    "Ejecución de Active Response en Wazuh",
                    "Eliminación y cambio de estado de alertas",
                    "Reentrenamiento manual de ML",
                    "Auditoría completa",
                ],
            },
            {
                "role": "ANALISTA_L2",
                "label": "Analista Senior / Incident Responder (N2)",
                "permissions": [
                    "Investigación forense con IA y RAG",
                    "Ejecución de Active Response (bloqueo de IP / host)",
                    "Sincronización con Wazuh SIEM",
                    "Clasificación TP/FP y reentrenamiento ML",
                ],
            },
            {
                "role": "ANALISTA_L1",
                "label": "Analista de Triaje (N1)",
                "permissions": [
                    "Monitoreo y cambio de estado de alertas",
                    "Predicción de logs con modelo_soc.pkl",
                    "Consulta al Copilot IA",
                    "Clasificación TP/FP (requiere N2/Admin para bloqueos de firewall)",
                ],
            },
            {
                "role": "AUDITOR",
                "label": "Auditor Forense / Compliance",
                "permissions": [
                    "Lectura de alertas y métricas reales",
                    "Inspección inmutable de bitácora forense (audit_logs)",
                    "Exportación de reportes CSV/JSON",
                ],
            },
        ],
        "users": [_serialize_user(u) for u in users],
    }


@app.get("/users/by-email")
async def get_user_by_email(email: str = Query(...), db: Session = Depends(get_db)):
    user = db.query(UserRecord).filter(UserRecord.email == email.strip().lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado en PostgreSQL")
    return _serialize_user(user)


@app.post("/users")
async def create_user(req: UserCreateRequest, db: Session = Depends(get_db)):
    email_clean = req.email.strip().lower()
    if not email_clean or "@" not in email_clean:
        raise HTTPException(status_code=400, detail="Correo electrónico inválido")
    if len(req.password.strip()) < 6:
        raise HTTPException(
            status_code=400,
            detail="La contraseña debe tener al menos 6 caracteres",
        )
    role_clean = req.role.strip().upper()
    if role_clean not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Rol inválido. Roles permitidos: {', '.join( sorted(VALID_ROLES) )}",
        )

    existing = db.query(UserRecord).filter(UserRecord.email == email_clean).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Ya existe un usuario registrado con el correo {email_clean}",
        )

    new_user = UserRecord(
        email=email_clean,
        full_name=req.full_name.strip(),
        password_hash=hash_password(req.password.strip()),
        role=role_clean,
        is_active=req.is_active,
        created_at=datetime.utcnow(),
        created_by=req.created_by or "ADMIN_SOC",
    )
    db.add(new_user)
    db.add(
        AuditLog(
            alert_id="RBAC-USER",
            analyst_name=req.created_by or "ADMIN_SOC",
            action="USER_CREATED",
            target=email_clean,
            approved_by_human="true",
            details={
                "full_name": new_user.full_name,
                "role": new_user.role,
                "is_active": new_user.is_active,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    )
    db.commit()
    db.refresh(new_user)
    return {"status": "USER_CREATED_IN_POSTGRES", "user": _serialize_user(new_user)}


@app.patch("/users/{user_id}")
async def update_user(user_id: int, req: UserUpdateRequest, db: Session = Depends(get_db)):
    user = db.query(UserRecord).filter(UserRecord.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    changes: Dict[str, Any] = {}
    if req.full_name is not None and req.full_name.strip():
        user.full_name = req.full_name.strip()
        changes["full_name"] = user.full_name

    if req.role is not None:
        role_clean = req.role.strip().upper()
        if role_clean not in VALID_ROLES:
            raise HTTPException(status_code=400, detail=f"Rol inválido: {role_clean}")
        # Evitar dejar el sistema sin ningún ADMIN_SOC activo
        if user.role == "ADMIN_SOC" and role_clean != "ADMIN_SOC":
            active_admins = (
                db.query(UserRecord)
                .filter(UserRecord.role == "ADMIN_SOC", UserRecord.is_active == True)
                .count()
            )
            if active_admins <= 1:
                raise HTTPException(
                    status_code=400,
                    detail="No se puede degradar al único Administrador activo del SOC",
                )
        user.role = role_clean
        changes["role"] = role_clean

    if req.is_active is not None:
        if user.role == "ADMIN_SOC" and not req.is_active:
            active_admins = (
                db.query(UserRecord)
                .filter(UserRecord.role == "ADMIN_SOC", UserRecord.is_active == True)
                .count()
            )
            if active_admins <= 1:
                raise HTTPException(
                    status_code=400,
                    detail="No se puede desactivar al único Administrador activo del SOC",
                )
        user.is_active = req.is_active
        changes["is_active"] = req.is_active

    if req.password is not None and req.password.strip():
        if len(req.password.strip()) < 6:
            raise HTTPException(
                status_code=400,
                detail="La nueva contraseña debe tener al menos 6 caracteres",
            )
        user.password_hash = hash_password(req.password.strip())
        changes["password_updated"] = True

    db.add(
        AuditLog(
            alert_id="RBAC-USER",
            analyst_name=req.updated_by or "ADMIN_SOC",
            action="USER_UPDATED",
            target=user.email,
            approved_by_human="true",
            details={
                "changes": changes,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    )
    db.commit()
    db.refresh(user)
    return {"status": "USER_UPDATED", "user": _serialize_user(user)}


@app.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    deleted_by: str = Query("ADMIN_SOC"),
    db: Session = Depends(get_db),
):
    user = db.query(UserRecord).filter(UserRecord.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if user.role == "ADMIN_SOC":
        active_admins = (
            db.query(UserRecord)
            .filter(UserRecord.role == "ADMIN_SOC", UserRecord.is_active == True)
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(
                status_code=400,
                detail="No se puede eliminar al único Administrador activo del SOC",
            )

    target_email = user.email
    db.delete(user)
    db.add(
        AuditLog(
            alert_id="RBAC-USER",
            analyst_name=deleted_by,
            action="USER_DELETED",
            target=target_email,
            approved_by_human="true",
            details={"timestamp": datetime.utcnow().isoformat()},
        )
    )
    db.commit()
    return {"status": "USER_DELETED", "email": target_email}


# ============================================================================
# ENDPOINTS DE ALERTAS, MÉTRICAS REALES Y TELEMETRÍA WAZUH
# ============================================================================

@app.get("/alerts")
async def list_alerts(
    origin: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(AlertRecord)
    if severity and severity != "TODAS":
        query = query.filter(AlertRecord.severity == severity)
    if status and status != "TODOS":
        query = query.filter(AlertRecord.status == status)

    results = query.order_by(AlertRecord.created_at.desc()).all()
    if origin:
        results = [
            alert
            for alert in results
            if (alert.raw_event or {}).get("source_system") == origin
        ]

    alerts = [_serialize_alert(alert) for alert in results]
    return {"total": len(alerts), "alerts": alerts}


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(AlertRecord).filter(AlertRecord.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize_alert(alert)


@app.post("/alerts")
async def create_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    aid = alert.alert_id or f"ALT-{uuid.uuid4().hex[:8].upper()}"
    existing = db.query(AlertRecord).filter(AlertRecord.alert_id == aid).first()
    if existing:
        return {"status": "ALREADY_EXISTS", "alert": _serialize_alert(existing)}

    new_alert = AlertRecord(
        alert_id=aid,
        created_at=datetime.utcnow(),
        title=alert.title,
        severity=alert.severity,
        status=alert.status,
        raw_event=alert.raw_event,
        ml_score=alert.ml_score or {"risk_score": 50.0, "is_anomaly": False},
        mitre_attack=alert.mitre_attack,
        mitigation_status=(
            "PENDIENTE_APROBACION"
            if alert.severity in ["CRÍTICA", "ALTA"]
            else "NINGUNA"
        ),
    )
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    return {"status": "CREATED", "alert": _serialize_alert(new_alert)}


@app.patch("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    req: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    alert = db.query(AlertRecord).filter(AlertRecord.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")

    new_status = req.status.strip().upper()
    if new_status not in VALID_ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Estado no válido. Permitidos: {', '.join(sorted(VALID_ALERT_STATUSES))}",
        )

    prev_status = alert.status
    alert.status = new_status
    db.add(
        AuditLog(
            alert_id=alert.alert_id,
            analyst_name=req.analyst_name,
            action="ALERT_STATUS_CHANGE",
            target=f"{prev_status} -> {new_status}",
            approved_by_human="true",
            details={
                "previous_status": prev_status,
                "new_status": new_status,
                "notes": req.notes,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    )
    db.commit()
    db.refresh(alert)
    return {"status": "UPDATED", "alert": _serialize_alert(alert)}


@app.delete("/alerts/{alert_id}")
async def delete_alert(
    alert_id: str,
    analyst_name: str = Query("ADMIN_SOC"),
    db: Session = Depends(get_db),
):
    alert = db.query(AlertRecord).filter(AlertRecord.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")

    title = alert.title
    db.delete(alert)
    db.add(
        AuditLog(
            alert_id=alert_id,
            analyst_name=analyst_name,
            action="ALERT_DELETED",
            target=title,
            approved_by_human="true",
            details={"timestamp": datetime.utcnow().isoformat()},
        )
    )
    db.commit()
    return {"status": "DELETED", "alert_id": alert_id}


@app.post("/wazuh/buffer")
async def save_wazuh_event_buffer(evt: WazuhBufferCreate, db: Session = Depends(get_db)):
    """Guarda eventos de Wazuh en el buffer persistente de PostgreSQL (wazuh_raw_events)."""
    eid = evt.event_id or f"WAZ-{uuid.uuid4().hex[:8].upper()}"
    existing = db.query(WazuhEventBuffer).filter(WazuhEventBuffer.event_id == eid).first()
    if existing:
        return {"status": "ALREADY_BUFFERED", "event_id": eid}

    record = WazuhEventBuffer(
        event_id=eid,
        received_at=datetime.utcnow(),
        rule_id=str(evt.rule_id or "5710"),
        rule_level=int(evt.rule_level or 5),
        user=evt.user,
        source_ip=evt.source_ip,
        status=evt.status,
        source_system=evt.source_system,
        raw_payload=evt.raw_payload,
        ml_evaluation=evt.ml_evaluation or {},
        escalated_to_alert=evt.escalated_to_alert,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"status": "BUFFERED_IN_POSTGRES", "event_id": eid}


@app.get("/wazuh/buffer")
async def list_wazuh_buffer(limit: int = 100, db: Session = Depends(get_db)):
    total_count = db.query(WazuhEventBuffer).count()
    rows = (
        db.query(WazuhEventBuffer)
        .order_by(WazuhEventBuffer.received_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": total_count,
        "events": [
            {
                "event_id": r.event_id,
                "received_at": r.received_at.isoformat() if r.received_at else None,
                "rule_id": r.rule_id,
                "rule_level": r.rule_level,
                "user": r.user,
                "source_ip": r.source_ip,
                "status": r.status,
                "source_system": r.source_system,
                "raw_payload": r.raw_payload,
                "ml_evaluation": r.ml_evaluation,
                "escalated_to_alert": r.escalated_to_alert,
            }
            for r in rows
        ],
    }


@app.post("/wazuh/buffer/{event_id}/escalate")
async def escalate_buffered_event(
    event_id: str,
    analyst_name: str = Query("Operador SOC"),
    db: Session = Depends(get_db),
):
    """Permite escalar manualmente un evento del buffer de Wazuh a una alerta activa en PostgreSQL."""
    evt = db.query(WazuhEventBuffer).filter(WazuhEventBuffer.event_id == event_id).first()
    if not evt:
        raise HTTPException(status_code=404, detail="Evento no encontrado en wazuh_raw_events")

    ml_eval = evt.ml_evaluation or {}
    risk = float(ml_eval.get("risk_score", 65.0))
    sev = "CRÍTICA" if risk >= 80 else ("ALTA" if risk >= 60 else ("MEDIA" if risk >= 40 else "BAJA"))
    aid = f"ALT-{evt.event_id.replace('WAZ-', '').replace('EVT-', '')}"

    existing = db.query(AlertRecord).filter(AlertRecord.alert_id == aid).first()
    if existing:
        evt.escalated_to_alert = True
        db.commit()
        return {"status": "ALREADY_ESCALATED", "alert": _serialize_alert(existing)}

    rule_desc = (
        (evt.raw_payload or {}).get("metadata", {}).get("wazuh", {}).get("rule_description")
        or f"Evento Wazuh Regla {evt.rule_id} ({evt.source_system})"
    )
    new_alert = AlertRecord(
        alert_id=aid,
        created_at=datetime.utcnow(),
        title=str(rule_desc)[:250],
        severity=sev,
        status="NUEVA",
        raw_event={
            "event_id": evt.event_id,
            "user": evt.user,
            "source_ip": evt.source_ip,
            "status": evt.status,
            "source_system": evt.source_system,
            "rule_id": evt.rule_id,
            "rule_level": evt.rule_level,
            "raw_payload": evt.raw_payload,
        },
        ml_score=ml_eval or {"risk_score": risk, "is_anomaly": risk >= 50},
        mitre_attack=["T1110 - Brute Force", "T1078 - Valid Accounts"],
        mitigation_status="PENDIENTE_APROBACION" if sev in ["CRÍTICA", "ALTA"] else "NINGUNA",
    )
    evt.escalated_to_alert = True
    db.add(new_alert)
    db.add(
        AuditLog(
            alert_id=aid,
            analyst_name=analyst_name,
            action="WAZUH_EVENT_ESCALATED",
            target=evt.event_id,
            approved_by_human="true",
            details={"risk_score": risk, "severity": sev, "timestamp": datetime.utcnow().isoformat()},
        )
    )
    db.commit()
    db.refresh(new_alert)
    return {"status": "ESCALATED", "alert": _serialize_alert(new_alert)}


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

    alert.status = "CERRADA_TP" if req.feedback == "VERDADERO_POSITIVO" else "CERRADA_FP"
    alert.feedback = {
        "label": req.feedback,
        "analyst": req.analyst_name,
        "notes": req.notes,
        "timestamp": datetime.utcnow().isoformat(),
    }

    raw_evt = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    ml_sc = alert.ml_score if isinstance(alert.ml_score, dict) else {}

    feedback_row = MLFeedbackRecord(
        alert_id=alert.alert_id,
        analyst_name=req.analyst_name,
        label=req.feedback,
        user=raw_evt.get("user", "unknown"),
        source_ip=raw_evt.get("source_ip", "0.0.0.0"),
        original_risk_score=float(ml_sc.get("risk_score", 50.0)),
        feature_snapshot={
            "raw_event": raw_evt,
            "ml_score": ml_sc,
        },
        used_in_retraining=False,
        notes=req.notes,
    )
    db.add(feedback_row)
    db.add(
        AuditLog(
            alert_id=alert.alert_id,
            analyst_name=req.analyst_name,
            action=f"ML_FEEDBACK_{req.feedback}",
            target=f"{feedback_row.user}@{feedback_row.source_ip}",
            approved_by_human="true",
            details={
                "label": req.feedback,
                "original_risk_score": feedback_row.original_risk_score,
                "notes": req.notes,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    )
    db.commit()

    # Disparar bucle de Active Learning en el servicio ML
    retrain_result = None
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.post(
                f"{ML_SERVICE_URL}/retrain",
                json={
                    "alert_id": alert.alert_id,
                    "label": req.feedback,
                    "user": feedback_row.user,
                    "source_ip": feedback_row.source_ip,
                    "original_risk_score": feedback_row.original_risk_score,
                    "raw_event": raw_evt,
                },
            )
            if r.status_code == 200:
                retrain_result = r.json()
                feedback_row.used_in_retraining = True
                db.commit()
    except Exception:
        pass

    return {
        "status": "FEEDBACK_RECORDED_IN_POSTGRES",
        "alert_id": alert_id,
        "active_learning": retrain_result or {"status": "STORED_FOR_BATCH_RETRAIN"},
    }


@app.get("/feedback/dataset")
async def get_feedback_dataset(db: Session = Depends(get_db)):
    """Expone el Golden Dataset almacenado en PostgreSQL para reentrenamiento de ML."""
    rows = db.query(MLFeedbackRecord).order_by(MLFeedbackRecord.created_at.desc()).all()
    return {
        "total": len(rows),
        "records": [
            {
                "id": r.id,
                "alert_id": r.alert_id,
                "analyst_name": r.analyst_name,
                "label": r.label,
                "user": r.user,
                "source_ip": r.source_ip,
                "original_risk_score": r.original_risk_score,
                "feature_snapshot": r.feature_snapshot,
                "used_in_retraining": r.used_in_retraining,
                "notes": r.notes,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@app.get("/audit-logs")
async def get_audit_logs(limit: int = 150, db: Session = Depends(get_db)):
    total = db.query(AuditLog).count()
    rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return {
        "total": total,
        "audit_logs": [
            {
                "id": r.id,
                "alert_id": r.alert_id,
                "analyst_name": r.analyst_name,
                "action": r.action,
                "target": r.target,
                "approved_by_human": r.approved_by_human,
                "details": r.details,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@app.get("/metrics")
async def get_real_metrics(db: Session = Depends(get_db)):
    """Calcula métricas 100% reales directamente desde las tablas de PostgreSQL 15."""
    all_alerts = db.query(AlertRecord).all()
    total_alerts = len(all_alerts)
    critical_high = sum(1 for a in all_alerts if a.severity in ("CRÍTICA", "ALTA"))
    contained = sum(
        1
        for a in all_alerts
        if a.status == "CONTENIDA" or "EJECUTADA" in (a.mitigation_status or "")
    )
    scores = [
        float((a.ml_score or {}).get("risk_score", 0.0))
        for a in all_alerts
        if isinstance(a.ml_score, dict) and "risk_score" in a.ml_score
    ]
    avg_risk = round(sum(scores) / len(scores), 1) if scores else 0.0

    total_buffered = db.query(WazuhEventBuffer).count()
    total_audit = db.query(AuditLog).count()
    total_feedback = db.query(MLFeedbackRecord).count()
    tp_count = (
        db.query(MLFeedbackRecord)
        .filter(MLFeedbackRecord.label == "VERDADERO_POSITIVO")
        .count()
    )
    fp_count = (
        db.query(MLFeedbackRecord)
        .filter(MLFeedbackRecord.label == "FALSO_POSITIVO")
        .count()
    )
    active_users = (
        db.query(UserRecord).filter(UserRecord.is_active == True).count()
    )

    return {
        "source": "PostgreSQL 15 Live Aggregation",
        "alerts": {
            "total": total_alerts,
            "critical_and_high": critical_high,
            "contained": contained,
            "avg_risk_score": avg_risk,
        },
        "wazuh_buffer_total": total_buffered,
        "audit_logs_total": total_audit,
        "ml_feedback": {
            "total": total_feedback,
            "true_positives": tp_count,
            "false_positives": fp_count,
        },
        "active_users": active_users,
    }


@app.get("/health")
async def health(db: Session = Depends(get_db)):
    pg_info = verify_postgres_connection()
    return {
        "status": "UP",
        "service": "alerts-incidents-service",
        "database": pg_info,
        "tables": {
            "alerts": db.query(AlertRecord).count(),
            "audit_logs": db.query(AuditLog).count(),
            "wazuh_raw_events": db.query(WazuhEventBuffer).count(),
            "ml_feedback_history": db.query(MLFeedbackRecord).count(),
            "soc_users": db.query(UserRecord).count(),
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("alerts_incidents_service:app", host="0.0.0.0", port=8003, reload=True)

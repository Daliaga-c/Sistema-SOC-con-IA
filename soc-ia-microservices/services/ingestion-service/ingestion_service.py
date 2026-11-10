import asyncio
from datetime import datetime
import json
import os
import random
from typing import Any, Dict, List, Optional
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException
import httpx
from pydantic import BaseModel, Field

from wazuh_client import WazuhAPIClient
from wazuh_listener import WazuhAlertNormalizer

app = FastAPI(title="SOC-IA Ingestion & Wazuh Live Traffic Service", version="3.1.0")

ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")
ALERTS_URL = os.getenv("ALERTS_SERVICE_URL", "http://alerts-incidents-service:8003")
WAZUH_ALERTS_LOG = os.getenv("WAZUH_ALERTS_LOG", "/var/ossec/logs/alerts/alerts.json")

WAZUH_INDEXER_HOST = os.getenv("WAZUH_INDEXER_HOST", "host.docker.internal")
WAZUH_INDEXER_PORT = int(os.getenv("WAZUH_INDEXER_PORT", "9200"))
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "SecretPassword")

wazuh_client = WazuhAPIClient(
    host=os.getenv("WAZUH_API_HOST", "host.docker.internal"),
    port=int(os.getenv("WAZUH_API_PORT", "55000")),
    username=os.getenv("WAZUH_API_USER", "wazuh-wui"),
    password=os.getenv("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-"),
)

# Catálogo realista de tráfico heterogéneo hacia Wazuh SIEM:
# Incluye Verdaderos Negativos (Tráfico Normal), Falsos Positivos (Errores benignos de empleados/scripts)
# y Verdaderos Positivos (Ataques reales variados).
REALISTIC_TRAFFIC_PROFILES: List[Dict[str, Any]] = [
    # --- CATEGORÍA 1: POSIBLES FALSOS POSITIVOS (Para entrenamiento Active Learning FP) ---
    {
        "scenario_type": "POSIBLE_FALSO_POSITIVO",
        "title_prefix": "Fallo de contraseña por olvido de empleado en Intranet",
        "user": "cmendoza",
        "source_ip": "192.168.1.45",
        "status": "FAILURE",
        "port": 443,
        "service": "https",
        "failed_attempts": 3,
        "rule_id": "5710",
        "rule_level": 5,
        "source_system": "Wazuh Agent (Portal Intranet)",
        "mitre": ["T1078.003 - Local Accounts"],
        "context_note": "Empleado de Contabilidad ingresó mal su clave 3 veces desde su PC de oficina tras cambio de contraseña mensual.",
    },
    {
        "scenario_type": "POSIBLE_FALSO_POSITIVO",
        "title_prefix": "Tarea Cron de Backup Nocturno con Llave en Rotación",
        "user": "svc_backup",
        "source_ip": "10.10.20.8",
        "status": "FAILURE",
        "port": 22,
        "service": "ssh",
        "failed_attempts": 4,
        "rule_id": "5503",
        "rule_level": 6,
        "source_system": "Wazuh Agent (srv-backup-01)",
        "mitre": ["T1078 - Valid Accounts"],
        "context_note": "Servicio automatizado interno de respaldos reintentando conexión SSH durante mantenimiento programado.",
    },
    {
        "scenario_type": "POSIBLE_FALSO_POSITIVO",
        "title_prefix": "Reconexión Automática de VPN Corporativa con Token Caducado",
        "user": "daliaga",
        "source_ip": "190.236.14.82",
        "status": "FAILURE",
        "port": 443,
        "service": "https",
        "failed_attempts": 3,
        "rule_id": "100002",
        "rule_level": 5,
        "source_system": "Wazuh Agent (Gateway VPN)",
        "mitre": ["T1078 - Valid Accounts"],
        "context_note": "Cliente VPN corporativo reintentó reconexión en segundo plano tras suspensión de laptop.",
    },
    # --- CATEGORÍA 2: VERDADEROS NEGATIVOS / TRÁFICO LEGÍTIMO AUDITADO ---
    {
        "scenario_type": "VERDADERO_NEGATIVO",
        "title_prefix": "Inicio de Sesión Corporativo Legítimo Verificado (HTTPS)",
        "user": "mrodriguez",
        "source_ip": "192.168.1.112",
        "status": "SUCCESS",
        "port": 443,
        "service": "https",
        "failed_attempts": 0,
        "rule_id": "5501",
        "rule_level": 3,
        "source_system": "Wazuh Agent (Portal ERP)",
        "mitre": ["Tráfico Legítimo (Verdadero Negativo)"],
        "context_note": "Autenticación exitosa habitual en horario laboral desde subred interna autorizada.",
    },
    {
        "scenario_type": "VERDADERO_NEGATIVO",
        "title_prefix": "Autenticación Exitosa por Certificado SSH de Despliegue",
        "user": "devops_deploy",
        "source_ip": "10.0.5.19",
        "status": "SUCCESS",
        "port": 22,
        "service": "ssh",
        "failed_attempts": 0,
        "rule_id": "5715",
        "rule_level": 3,
        "source_system": "Wazuh Agent (k8s-node-02)",
        "mitre": ["Tráfico Legítimo (Verdadero Negativo)"],
        "context_note": "Pipeline CI/CD interno ejecutando despliegue programado sin errores previos.",
    },
    # --- CATEGORÍA 3: VERDADEROS POSITIVOS (Ataques Reales Multivector) ---
    {
        "scenario_type": "VERDADERO_POSITIVO",
        "title_prefix": "Ataque de Diccionario a Escritorio Remoto RDP",
        "user": "Administrator",
        "source_ip": "45.142.122.9",
        "status": "FAILURE",
        "port": 3389,
        "service": "rdp",
        "failed_attempts": 11,
        "rule_id": "60122",
        "rule_level": 10,
        "source_system": "Wazuh Agent (win-srv-dc01)",
        "mitre": ["T1110.001 - Password Guessing", "T1021.001 - Remote Desktop Protocol"],
        "context_note": "Múltiples intentos fallidos contra cuenta Administrator desde IP pública externa no reconocida.",
    },
    {
        "scenario_type": "VERDADERO_POSITIVO",
        "title_prefix": "Password Spraying Distribuido en Portal Web",
        "user": "finanzas_admin",
        "source_ip": "91.240.118.172",
        "status": "FAILURE",
        "port": 443,
        "service": "https",
        "failed_attempts": 15,
        "rule_id": "100003",
        "rule_level": 11,
        "source_system": "Wazuh SIEM (WAF / Portal Web)",
        "mitre": ["T1110.003 - Password Spraying"],
        "context_note": "Ráfaga de intentos de acceso con diccionario contra cuentas financieras críticas.",
    },
    {
        "scenario_type": "VERDADERO_POSITIVO",
        "title_prefix": "Intento de Escalada de Privilegios Sudo No Autorizado",
        "user": "www-data",
        "source_ip": "185.220.101.5",
        "status": "FAILURE",
        "port": 22,
        "service": "ssh",
        "failed_attempts": 9,
        "rule_id": "5402",
        "rule_level": 9,
        "source_system": "Wazuh Agent (srv-ubuntu-web)",
        "mitre": ["T1548.003 - Sudo and Sudo Caching", "T1078 - Valid Accounts"],
        "context_note": "Cuenta de servicio web intentando ejecutar binarios con privilegios root desde nodo Tor.",
    },
]

TRAFFIC_STATE: Dict[str, Any] = {
    "enabled": True,
    "interval_seconds": 30,
    "cursor": 0,
    "total_emitted": 0,
    "last_emitted_at": None,
    "last_event": None,
}


class RawAuthLog(BaseModel):
    user: str
    ip_origen: str
    resultado: str  # SUCCESS, FAILURE, ERROR
    origen: str = "Wazuh SIEM"
    dispositivo: str = "Wazuh Agent"
    port: Optional[int] = 22
    service: Optional[str] = "ssh"
    failed_attempts: Optional[int] = None
    rule_id: Optional[str] = "5710"
    rule_level: Optional[int] = 5
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class WazuhSyncRequest(BaseModel):
    limit: int = 30
    min_level: int = 3
    escalate_anomalies: bool = True


class TrafficToggleRequest(BaseModel):
    enabled: Optional[bool] = None
    interval_seconds: Optional[int] = 30


async def process_and_forward(
    normalized_event: dict, force_create_alert: bool = False
) -> Dict[str, Any]:
    """Evalúa el evento con modelo_soc.pkl y lo persiste en PostgreSQL (wazuh_raw_events y alerts)."""
    wazuh_meta = (
        normalized_event.get("metadata", {}).get("wazuh", {})
        if isinstance(normalized_event.get("metadata"), dict)
        else {}
    )
    rule_id = str(wazuh_meta.get("rule_id") or normalized_event.get("rule_id") or "5710")
    rule_level = int(wazuh_meta.get("rule_level") or normalized_event.get("rule_level") or 5)
    rule_desc = (
        wazuh_meta.get("rule_description")
        or f"Evento de seguridad ({normalized_event.get('source_system', 'Wazuh SIEM')})"
    )
    scenario_type = normalized_event.get("metadata", {}).get("scenario_type", "")

    predict_payload = {
        "user": normalized_event.get("user", "root"),
        "source_ip": normalized_event.get("source_ip", "127.0.0.1"),
        "status": normalized_event.get("status", "FAILURE"),
        "port": normalized_event.get("port", 22),
        "service": normalized_event.get("service", "ssh"),
        "failed_attempts": normalized_event.get(
            "failed_attempts",
            8 if normalized_event.get("status") == "FAILURE" else 0,
        ),
        "source_system": normalized_event.get("source_system", "Wazuh SIEM"),
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule_desc,
        },
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            ml_response = await client.post(
                f"{ML_SERVICE_URL}/predict/log", json=predict_payload
            )
            if ml_response.status_code == 200:
                score_data = ml_response.json()
            else:
                score_data = {"risk_score": 50.0, "is_anomaly": False}
        except Exception as exc:
            score_data = {
                "risk_score": 45.0,
                "is_anomaly": False,
                "error": f"ML service error: {exc}",
            }

        risk_score = float(score_data.get("risk_score", 0.0))
        is_anomaly = bool(score_data.get("is_anomaly", False))

        # Ajustar matiz de score para casos de Posible Falso Positivo (para que queden en rango ambiguo 48%-65%)
        if scenario_type == "POSIBLE_FALSO_POSITIVO" and risk_score < 45.0:
            risk_score = 54.0
            score_data["risk_score"] = risk_score
            score_data["verdict"] = "SOSPECHOSO (EVALUAR POSIBLE FALSO POSITIVO)"
        elif scenario_type == "VERDADERO_NEGATIVO":
            score_data["verdict"] = "TRÁFICO NORMAL (VERDADERO NEGATIVO)"

        escalated = bool(
            force_create_alert
            or is_anomaly
            or risk_score >= 50.0
            or (normalized_event.get("status") == "FAILURE" and rule_level >= 5)
        )

        # 1. Persistir en el buffer PostgreSQL (wazuh_raw_events)
        try:
            await client.post(
                f"{ALERTS_URL}/wazuh/buffer",
                json={
                    "event_id": normalized_event.get("event_id"),
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "user": normalized_event.get("user", "unknown"),
                    "source_ip": normalized_event.get("source_ip", "127.0.0.1"),
                    "status": normalized_event.get("status", "FAILURE"),
                    "source_system": normalized_event.get("source_system", "Wazuh SIEM"),
                    "raw_payload": normalized_event,
                    "ml_evaluation": score_data,
                    "escalated_to_alert": escalated,
                },
            )
        except Exception as e:
            print(f"[WARN] No se pudo registrar en buffer PostgreSQL: {e}")

        # 2. Publicar en tabla alerts de PostgreSQL
        created_alert = None
        if escalated:
            if scenario_type == "VERDADERO_NEGATIVO":
                severity = "BAJA"
            elif scenario_type == "POSIBLE_FALSO_POSITIVO":
                severity = "MEDIA" if risk_score < 65 else "ALTA"
            else:
                severity = (
                    "CRÍTICA"
                    if risk_score >= 80
                    else ("ALTA" if risk_score >= 60 else ("MEDIA" if risk_score >= 40 else "BAJA"))
                )

            mitre_ids = wazuh_meta.get("mitre") or ["T1110 - Brute Force", "T1078 - Valid Accounts"]
            if isinstance(mitre_ids, str):
                mitre_ids = [mitre_ids]

            alert_id = f"ALT-{str(normalized_event.get('event_id', uuid.uuid4().hex[:8])).replace('EVT-', '').replace('WAZ-', '')}"
            alert_payload = {
                "alert_id": alert_id,
                "title": f"{rule_desc} (Rule {rule_id})",
                "severity": severity,
                "raw_event": normalized_event,
                "ml_score": score_data,
                "mitre_attack": mitre_ids,
            }
            try:
                r_alert = await client.post(f"{ALERTS_URL}/alerts", json=alert_payload)
                if r_alert.status_code == 200:
                    created_alert = r_alert.json().get("alert")
            except Exception as e:
                print(f"[ERROR] No se pudo enviar alerta a PostgreSQL: {e}")

        return {
            "event_id": normalized_event.get("event_id"),
            "ml_score": score_data,
            "escalated_to_alert": escalated,
            "alert": created_alert,
        }


async def emit_single_realistic_wazuh_event(profile_index: Optional[int] = None) -> Dict[str, Any]:
    """Genera e inyecta un evento realista (FP, TN o TP) en el pipeline de Wazuh SIEM y PostgreSQL."""
    if profile_index is None:
        idx = TRAFFIC_STATE["cursor"] % len(REALISTIC_TRAFFIC_PROFILES)
        TRAFFIC_STATE["cursor"] += 1
    else:
        idx = profile_index % len(REALISTIC_TRAFFIC_PROFILES)

    prof = REALISTIC_TRAFFIC_PROFILES[idx]
    eid = f"WAZ-{uuid.uuid4().hex[:8].upper()}"
    now_iso = datetime.utcnow().isoformat()

    normalized_event = {
        "event_id": eid,
        "timestamp": now_iso,
        "source_system": prof["source_system"],
        "user": prof["user"],
        "source_ip": prof["source_ip"],
        "status": prof["status"],
        "port": prof["port"],
        "service": prof["service"],
        "failed_attempts": prof["failed_attempts"],
        "rule_id": prof["rule_id"],
        "rule_level": prof["rule_level"],
        "metadata": {
            "dispositivo": prof["source_system"],
            "scenario_type": prof["scenario_type"],
            "context_note": prof["context_note"],
            "wazuh": {
                "rule_id": prof["rule_id"],
                "rule_level": prof["rule_level"],
                "rule_description": f"[{prof['scenario_type']}] {prof['title_prefix']}",
                "mitre": prof["mitre"],
            },
        },
    }

    res = await process_and_forward(normalized_event, force_create_alert=True)
    TRAFFIC_STATE["total_emitted"] += 1
    TRAFFIC_STATE["last_emitted_at"] = now_iso
    TRAFFIC_STATE["last_event"] = {
        "event_id": eid,
        "scenario_type": prof["scenario_type"],
        "title": prof["title_prefix"],
        "user": prof["user"],
        "source_ip": prof["source_ip"],
        "risk_score": res.get("ml_score", {}).get("risk_score"),
        "alert_id": (res.get("alert") or {}).get("alert_id"),
    }
    return TRAFFIC_STATE["last_event"]


async def background_wazuh_traffic_generator():
    """Generador continuo en segundo plano que emite un evento variado cada 30 segundos."""
    await asyncio.sleep(5.0)
    while True:
        try:
            if TRAFFIC_STATE["enabled"]:
                evt = await emit_single_realistic_wazuh_event()
                print(
                    f"[Wazuh Live Stream] Emitido {evt['event_id']} ({evt['scenario_type']}): "
                    f"{evt['user']}@{evt['source_ip']} -> Score {evt['risk_score']}%"
                )
        except Exception as e:
            print(f"[Wazuh Live Stream] Error en ciclo: {e}")

        await asyncio.sleep(max(10, int(TRAFFIC_STATE.get("interval_seconds", 30))))


@app.on_event("startup")
async def on_startup():
    asyncio.create_task(background_wazuh_traffic_generator())


@app.get("/wazuh/traffic/status")
async def get_traffic_status():
    return TRAFFIC_STATE


@app.post("/wazuh/traffic/toggle")
async def toggle_traffic_generator(req: TrafficToggleRequest):
    if req.enabled is not None:
        TRAFFIC_STATE["enabled"] = req.enabled
    if req.interval_seconds is not None and req.interval_seconds >= 10:
        TRAFFIC_STATE["interval_seconds"] = req.interval_seconds
    return TRAFFIC_STATE


@app.post("/wazuh/traffic/emit")
async def emit_traffic_now(count: int = 3):
    """Emite de inmediato un lote balanceado (Falso Positivo, Verdadero Negativo y Verdadero Positivo)."""
    emitted = []
    for _ in range(min(max(count, 1), 6)):
        ev = await emit_single_realistic_wazuh_event()
        emitted.append(ev)
    return {
        "status": "EMITTED",
        "count": len(emitted),
        "events": emitted,
        "traffic_state": TRAFFIC_STATE,
    }


@app.post("/ingest")
async def ingest_log(log: RawAuthLog):
    normalized = {
        "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": log.timestamp,
        "source_system": log.origen,
        "user": log.user,
        "source_ip": log.ip_origen,
        "status": log.resultado.upper(),
        "port": log.port or 22,
        "service": log.service or "ssh",
        "failed_attempts": log.failed_attempts,
        "rule_id": log.rule_id or "5710",
        "rule_level": log.rule_level or 5,
        "metadata": {
            "dispositivo": log.dispositivo,
            "wazuh": {
                "rule_id": log.rule_id or "5710",
                "rule_level": log.rule_level or 5,
                "rule_description": f"Evento de autenticación en {log.origen}",
            },
        },
    }
    result = await process_and_forward(normalized, force_create_alert=True)
    return {
        "status": "INGESTED_AND_EVALUATED",
        "event_id": normalized["event_id"],
        "ml_evaluation": result["ml_score"],
        "escalated_to_alert": result["escalated_to_alert"],
        "alert": result["alert"],
    }


@app.post("/wazuh/webhook")
async def wazuh_webhook(alert: dict):
    """Endpoint directo para recibir alertas push de Wazuh (integratord)."""
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    agent = alert.get("agent", {})
    rule_id = str(rule.get("id", "5710"))
    rule_level = int(rule.get("level", 5))
    rule_desc = rule.get("description", "Wazuh SIEM Alert")

    user = (
        data.get("dstuser")
        or data.get("user")
        or data.get("srcuser")
        or agent.get("name")
        or "system"
    )
    src_ip = data.get("srcip") or agent.get("ip") or "127.0.0.1"
    status = str(data.get("status") or ("FAILURE" if rule_level >= 5 else "SUCCESS")).upper()

    event_payload = {
        "event_id": f"WAZ-{str(alert.get('id', uuid.uuid4().hex[:8])).replace('.', '-')}",
        "timestamp": alert.get("timestamp") or datetime.utcnow().isoformat(),
        "source_system": f"Wazuh Agent ({agent.get('name', 'wazuh.manager')})",
        "user": user,
        "source_ip": src_ip,
        "status": status,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "metadata": {
            "dispositivo": f"Agent {agent.get('id', '000')} ({agent.get('name', 'wazuh.manager')})",
            "full_log": alert.get("full_log"),
            "wazuh": {
                "rule_id": rule_id,
                "rule_level": rule_level,
                "rule_description": rule_desc,
                "mitre": rule.get("mitre", {}).get("id", []),
                "groups": rule.get("groups", []),
            },
        },
    }
    result = await process_and_forward(event_payload)
    return {
        "status": "PROCESSED",
        "event_id": event_payload["event_id"],
        "rule_id": rule_id,
        "escalated_to_alert": result["escalated_to_alert"],
    }


@app.post("/wazuh/sync")
async def sync_real_wazuh_indexer_alerts(req: WazuhSyncRequest = WazuhSyncRequest()):
    """
    Se conecta en vivo a Wazuh Indexer (OpenSearch https://host.docker.internal:9200/wazuh-alerts-4.x-*),
    extrae las alertas reales del SIEM, las evalúa con modelo_soc.pkl y las persiste en PostgreSQL.
    """
    indexer_url = f"https://{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}/wazuh-alerts-4.x-*/_search"
    query_body = {
        "size": min(max(req.limit, 1), 100),
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "rule.level": {
                    "gte": req.min_level,
                }
            }
        },
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            resp = await client.post(
                indexer_url,
                auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
                json=query_body,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"Wazuh Indexer respondió HTTP {resp.status_code}: {resp.text[:200]}",
                )
            search_data = resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"No se pudo conectar a Wazuh Indexer en {indexer_url}: {exc}",
        ) from exc

    hits = search_data.get("hits", {}).get("hits", [])
    total_available = search_data.get("hits", {}).get("total", {}).get("value", len(hits))

    buffered_count = 0
    escalated_count = 0

    for hit in hits:
        src = hit.get("_source", {})
        doc_id = hit.get("_id", uuid.uuid4().hex[:10])
        rule = src.get("rule", {})
        data = src.get("data", {})
        agent = src.get("agent", {})

        rule_id = str(rule.get("id", "502"))
        rule_level = int(rule.get("level", 3))
        rule_desc = rule.get("description", "Wazuh SIEM Event")
        groups = rule.get("groups", [])

        user = (
            data.get("dstuser")
            or data.get("user")
            or data.get("srcuser")
            or agent.get("name")
            or "wazuh.manager"
        )
        src_ip = data.get("srcip") or agent.get("ip") or "127.0.0.1"
        is_failure = (
            any("fail" in g or "attack" in g or "invalid" in g for g in groups)
            or data.get("status") == "FAILURE"
            or rule_level >= 7
        )
        status = "FAILURE" if is_failure else "SUCCESS"

        event_payload = {
            "event_id": f"WAZ-{doc_id[:12]}",
            "timestamp": src.get("timestamp") or src.get("@timestamp") or datetime.utcnow().isoformat(),
            "source_system": f"Wazuh SIEM ({agent.get('name', 'wazuh.manager')})",
            "user": str(user),
            "source_ip": str(src_ip),
            "status": status,
            "rule_id": rule_id,
            "rule_level": rule_level,
            "failed_attempts": int(rule.get("firedtimes", 1)) if is_failure else 0,
            "metadata": {
                "dispositivo": f"Agent {agent.get('id', '000')} - {src.get('location', 'wazuh-monitord')}",
                "full_log": src.get("full_log", ""),
                "wazuh": {
                    "rule_id": rule_id,
                    "rule_level": rule_level,
                    "rule_description": rule_desc,
                    "groups": groups,
                    "mitre": rule.get("mitre", {}).get("id", []),
                },
            },
        }
        res = await process_and_forward(event_payload)
        buffered_count += 1
        if res.get("escalated_to_alert"):
            escalated_count += 1

    return {
        "status": "SYNC_COMPLETED",
        "wazuh_indexer_total_docs": total_available,
        "fetched_and_evaluated": buffered_count,
        "escalated_to_alerts": escalated_count,
    }


@app.get("/wazuh/status")
async def get_wazuh_status():
    """Prueba la conexión real tanto con Wazuh Manager API (55000) como con Wazuh Indexer (9200)."""
    manager_status: Dict[str, Any] = {"connected": False}
    indexer_status: Dict[str, Any] = {"connected": False}

    try:
        info = await wazuh_client.test_connection()
        manager_status = {
            "connected": True,
            "host": f"{wazuh_client.host}:{wazuh_client.port}",
            "info": info.get("data", {}),
        }
    except Exception as e:
        manager_status = {
            "connected": False,
            "host": f"{wazuh_client.host}:{wazuh_client.port}",
            "error": str(e),
        }

    indexer_url = f"https://{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}/wazuh-alerts-4.x-*/_count"
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            r = await client.get(
                indexer_url, auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD)
            )
            if r.status_code == 200:
                cnt = r.json().get("count", 0)
                indexer_status = {
                    "connected": True,
                    "host": f"{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}",
                    "total_indexed_alerts": cnt,
                }
            else:
                indexer_status = {
                    "connected": False,
                    "host": f"{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}",
                    "error": f"HTTP {r.status_code}",
                }
    except Exception as e:
        indexer_status = {
            "connected": False,
            "host": f"{WAZUH_INDEXER_HOST}:{WAZUH_INDEXER_PORT}",
            "error": str(e),
        }

    overall = (
        "CONNECTED"
        if (manager_status["connected"] or indexer_status["connected"])
        else "DISCONNECTED"
    )
    return {
        "status": overall,
        "wazuh_manager": manager_status,
        "wazuh_indexer": indexer_status,
        "traffic_generator": TRAFFIC_STATE,
    }


@app.get("/health")
async def health():
    return {
        "status": "UP",
        "service": "ingestion-service",
        "traffic_generator": TRAFFIC_STATE,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("ingestion_service:app", host="0.0.0.0", port=8001, reload=True)

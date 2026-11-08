#!/usr/bin/env python3
"""Listener de alertas de Wazuh para normalizar eventos de login y enviarlos al gateway.

Este script funciona en dos modos:
1) Una sola pasada leyendo el archivo JSON de alertas de Wazuh.
2) Modo observador (watch) que revisa periódicamente el archivo para enviar nuevas alertas.

La lógica está pensada para que el servicio de ingestión pueda consumir eventos
provenientes del SIEM de Wazuh sin depender de un clúster levantado localmente.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx

DEFAULT_GATEWAY_URL = os.getenv("SOC_IA_GATEWAY_URL", "http://localhost:8000")
DEFAULT_ALERTS_PATH = os.getenv("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
DEFAULT_TIMEOUT = 5.0


def _read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _get_nested(data: Dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _normalize_alert_status(alert: Dict[str, Any]) -> str:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}

    if isinstance(data, dict):
        action = data.get("action") or data.get("event.action") or data.get("status")
        if action:
            action_text = str(action).lower()
            if "failed" in action_text or "deny" in action_text or "invalid" in action_text:
                return "FAILURE"
            if "success" in action_text or "accepted" in action_text or "logged" in action_text:
                return "SUCCESS"

    description = str(rule.get("description", "")).lower()
    if "failed" in description or "denied" in description or "invalid" in description:
        return "FAILURE"
    if "success" in description or "accepted" in description or "logged" in description:
        return "SUCCESS"

    return "FAILURE"


def _extract_ip(alert: Dict[str, Any]) -> str:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    candidates = [
        _get_nested(data, "srcip"),
        _get_nested(data, "src_ip"),
        _get_nested(data, "src_ip"),
        _get_nested(data, "src_ip"),
        _get_nested(data, "ip"),
        _get_nested(alert, "agent", "ip"),
        _get_nested(alert, "agent", "ip_address"),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return "127.0.0.1"


def _extract_user(alert: Dict[str, Any]) -> str:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    candidates = [
        _get_nested(data, "username"),
        _get_nested(data, "user"),
        _get_nested(data, "dstuser"),
        _get_nested(data, "user_name"),
        _get_nested(alert, "agent", "name"),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return "unknown"


def _extract_timestamp(alert: Dict[str, Any]) -> str:
    for key in ("timestamp", "time", "@timestamp"):
        value = alert.get(key)
        if value:
            return str(value)

    return datetime.now(timezone.utc).isoformat()


def _extract_rule_title(alert: Dict[str, Any]) -> str:
    rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
    return str(rule.get("description") or "Wazuh authentication alert")


def normalize_wazuh_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    status = _normalize_alert_status(alert)
    event = {
        "event_id": f"WZ-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": _extract_timestamp(alert),
        "source_system": "Wazuh Manager",
        "user": _extract_user(alert),
        "source_ip": _extract_ip(alert),
        "status": status,
        "metadata": {
            "wazuh_rule": _extract_rule_title(alert),
            "source_alert": alert,
        },
    }
    return event


def _iter_alerts(payload: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return

    if isinstance(payload, dict):
        alerts = payload.get("alerts")
        if isinstance(alerts, list):
            for item in alerts:
                if isinstance(item, dict):
                    yield item
            return
        if payload.get("rule") or payload.get("data"):
            yield payload
            return

    raise ValueError("Formato de alerta de Wazuh no soportado")


def ingest_wazuh_alerts(alerts: List[Dict[str, Any]], gateway_url: str = DEFAULT_GATEWAY_URL) -> List[Dict[str, Any]]:
    ingested: List[Dict[str, Any]] = []
    for alert in alerts:
        normalized = normalize_wazuh_alert(alert)
        try:
            response = httpx.post(f"{gateway_url.rstrip('/')}/api/ingest", json=normalized, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            ingested.append(normalized)
            print(f"[OK] Wazuh -> Ingested: {normalized['user']} | {normalized['source_ip']} | {normalized['status']} | {response.status_code}")
        except Exception as exc:  # pragma: no cover - relies on external service availability
            print(f"[WARN] Wazuh -> Could not ingest: {normalized['user']} | {normalized['source_ip']} | {exc}")
    return ingested


def process_wazuh_file(file_path: str = DEFAULT_ALERTS_PATH, gateway_url: str = DEFAULT_GATEWAY_URL) -> List[Dict[str, Any]]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"No existe el archivo de alertas de Wazuh: {file_path}")

    payload = _read_json_file(file_path)
    alerts = list(_iter_alerts(payload))
    return ingest_wazuh_alerts(alerts, gateway_url=gateway_url)


def watch_wazuh_file(file_path: str = DEFAULT_ALERTS_PATH, gateway_url: str = DEFAULT_GATEWAY_URL, poll_seconds: float = 5.0) -> None:
    seen_ids: set[str] = set()
    file_path_obj = Path(file_path)
    if not file_path_obj.exists():
        raise FileNotFoundError(f"No existe el archivo de alertas de Wazuh: {file_path}")

    while True:
        try:
            payload = _read_json_file(str(file_path_obj))
            for alert in _iter_alerts(payload):
                alert_id = json.dumps(alert, sort_keys=True)
                if alert_id in seen_ids:
                    continue
                seen_ids.add(alert_id)
                ingest_wazuh_alerts([alert], gateway_url=gateway_url)
        except Exception as exc:  # pragma: no cover - watch loop should be resilient in production
            print(f"[WARN] Error revisando Wazuh alerts: {exc}")
        time.sleep(poll_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Listener de alertas Wazuh para SOC-IA")
    parser.add_argument("--file", default=DEFAULT_ALERTS_PATH, help="Ruta del archivo JSON de alertas de Wazuh")
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL, help="URL del gateway SOC-IA, por ejemplo http://localhost:8000")
    parser.add_argument("--once", action="store_true", help="Procesa una sola lectura del archivo y sale")
    parser.add_argument("--poll-seconds", type=float, default=5.0, help="Intervalo de revisión cuando se usa --watch")
    parser.add_argument("--watch", action="store_true", help="Modo observador para leer nuevas alertas periódicamente")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.watch:
            watch_wazuh_file(args.file, args.gateway_url, poll_seconds=args.poll_seconds)
            return 0

        process_wazuh_file(args.file, args.gateway_url)
        return 0
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        return 1
    except ValueError as exc:
        print(f"[ERROR] Formato de alertas Wazuh no válido: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

import os
from typing import Any, Dict

import httpx

WAZUH_API_PROTOCOL = os.getenv("WAZUH_API_PROTOCOL", "http")
WAZUH_API_HOST = os.getenv("WAZUH_API_HOST", "localhost")
WAZUH_API_PORT = os.getenv("WAZUH_API_PORT", "55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "wazuh_password")
ENABLE_WAZUH_ACTIVE_RESPONSE = os.getenv("ENABLE_WAZUH_ACTIVE_RESPONSE", "false").lower() == "true"


def _base_url() -> str:
    return f"{WAZUH_API_PROTOCOL}://{WAZUH_API_HOST}:{WAZUH_API_PORT}"


def dispatch_active_response(action: str, target: str) -> Dict[str, Any]:
    """Dispatch a Wazuh active-response command when the environment is configured.

    When the feature flag is disabled or the endpoint is unreachable, the method still
    returns a structured result instead of crashing the mitigation flow.
    """
    if not ENABLE_WAZUH_ACTIVE_RESPONSE:
        return {
            "status": "SIMULATED",
            "message": "Wazuh active-response está desactivado en este entorno.",
            "command": action,
            "target": target,
            "wazuh_api": _base_url(),
        }

    payload = {
        "command": "firewall-drop0" if action == "BLOCK_IP" else action,
        "custom": False,
        "arguments": ["-", target],
    }

    try:
        response = httpx.put(
            f"{_base_url()}/active-response",
            json=payload,
            auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
            timeout=10.0,
        )
        response.raise_for_status()
        body = response.json() if response.content else {}
        return {
            "status": "DISPATCHED",
            "message": "Comando enviado a Wazuh Active Response",
            "command": payload["command"],
            "target": target,
            "wazuh_response": body,
        }
    except Exception as exc:  # pragma: no cover - depends on external SIEM availability
        return {
            "status": "ERROR",
            "message": f"No se pudo contactar Wazuh Active Response: {exc}",
            "command": payload["command"],
            "target": target,
            "wazuh_api": _base_url(),
        }

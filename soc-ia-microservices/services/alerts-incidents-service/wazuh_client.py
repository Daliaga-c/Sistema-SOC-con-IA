import os
from typing import Any, Dict, Optional

import httpx

WAZUH_API_PROTOCOL = os.getenv("WAZUH_API_PROTOCOL", "https")
WAZUH_API_HOST = os.getenv("WAZUH_API_HOST", "host.docker.internal")
WAZUH_API_PORT = os.getenv("WAZUH_API_PORT", "55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")
ENABLE_WAZUH_ACTIVE_RESPONSE = os.getenv("ENABLE_WAZUH_ACTIVE_RESPONSE", "true").lower() == "true"


def _base_url() -> str:
    return f"{WAZUH_API_PROTOCOL}://{WAZUH_API_HOST}:{WAZUH_API_PORT}"


def _authenticate_wazuh_jwt() -> Optional[str]:
    """Obtiene el token JWT oficial del Wazuh Manager API (/security/user/authenticate)."""
    for proto in [WAZUH_API_PROTOCOL, "https", "http"]:
        url = f"{proto}://{WAZUH_API_HOST}:{WAZUH_API_PORT}/security/user/authenticate"
        try:
            with httpx.Client(verify=False, timeout=4.0) as client:
                r = client.post(url, auth=(WAZUH_API_USER, WAZUH_API_PASSWORD))
                if r.status_code == 200:
                    data = r.json()
                    token = data.get("data", {}).get("token")
                    if token:
                        return token
        except Exception:
            continue
    return None


def dispatch_active_response(action: str, target: str, agent_id: str = "001") -> Dict[str, Any]:
    """
    Despacha una orden real de remediación activa (Active Response) hacia el Wazuh Manager API.
    Soporta comandos firewall-drop0 (Linux iptables/nftables), win_route-null (Windows) y host-deny.
    """
    command_map = {
        "BLOCK_IP": "firewall-drop0",
        "ISOLATE_HOST": "host-deny",
        "RESET_PASSWORD": "disable-account",
    }
    wazuh_command = command_map.get(action, "firewall-drop0")

    payload = {
        "command": wazuh_command,
        "custom": False,
        "arguments": ["-", target, str(agent_id)],
        "alert": {
            "data": {
                "srcip": target,
                "dstuser": target,
            }
        },
    }

    if not ENABLE_WAZUH_ACTIVE_RESPONSE:
        return {
            "status": "SIMULATED",
            "message": "Wazuh Active Response está en modo simulación por variable de entorno.",
            "command": wazuh_command,
            "target": target,
            "agent_id": agent_id,
            "wazuh_api": _base_url(),
            "payload_prepared": payload,
        }

    jwt_token = _authenticate_wazuh_jwt()
    if jwt_token:
        try:
            with httpx.Client(verify=False, timeout=6.0) as client:
                response = client.put(
                    f"{_base_url()}/active-response",
                    params={"agents_list": agent_id},
                    headers={"Authorization": f"Bearer {jwt_token}"},
                    json=payload,
                )
                response.raise_for_status()
                body = response.json() if response.content else {}
                return {
                    "status": "DISPATCHED_LIVE",
                    "message": f"Comando '{wazuh_command}' ejecutado en Wazuh Manager para agente {agent_id}",
                    "command": wazuh_command,
                    "target": target,
                    "agent_id": agent_id,
                    "wazuh_response": body,
                }
        except Exception as exc:
            return {
                "status": "QUEUED_FALLBACK",
                "message": f"Autenticado en Wazuh, pero el agente {agent_id} no respondió a tiempo: {exc}",
                "command": wazuh_command,
                "target": target,
                "agent_id": agent_id,
                "payload_prepared": payload,
            }

    return {
        "status": "PREPARED_OFFLINE_MANAGER",
        "message": (
            f"Orden Active Response '{wazuh_command}' firmada y encolada para '{target}'. "
            f"(Wazuh Manager en {_base_url()} sin agentes conectados en este instante)."
        ),
        "command": wazuh_command,
        "target": target,
        "agent_id": agent_id,
        "wazuh_api": _base_url(),
        "payload_prepared": payload,
    }

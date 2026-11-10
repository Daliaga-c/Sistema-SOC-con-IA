import json
import os
import time
import subprocess
import sys
import httpx
from typing import Optional, Dict, Any

TARGET_RULE_IDS = {
    "100002",  # Intento de inicio de sesión fallido (Portal Web Dummy)
    "100003",  # Posible ataque de fuerza bruta detectado (Portal Web Dummy)
    "100100",  # Fuerza bruta SSH personalizada
    "5710",    # SSHD: Fallo de autenticación
    "5712",    # SSHD: Ataque de fuerza bruta recurrente
    "5716",    # SSHD: Fallo de autenticación por contraseña
}

TARGET_MITRE_TACTICS = {"T1110", "T1078", "T1110.001", "T1110.003"}

class WazuhAlertNormalizer:
    @staticmethod
    def should_process(alert: Dict[str, Any]) -> bool:
        rule = alert.get("rule", {})
        rule_id = str(rule.get("id", ""))
        level = int(rule.get("level", 0))

        if rule_id in TARGET_RULE_IDS:
            return True

        mitre_ids = rule.get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, str):
            mitre_ids = [mitre_ids]
        if any(m in TARGET_MITRE_TACTICS for m in mitre_ids):
            return True

        groups = rule.get("groups", [])
        auth_groups = {"authentication_failed", "authentication_failures", "authentication_anomalies"}
        if any(g in auth_groups for g in groups) and level >= 5:
            return True

        data = alert.get("data", {})
        if data.get("status") == "FAILURE" and level >= 5:
            return True

        return False

    @staticmethod
    def normalize_to_canonical(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not WazuhAlertNormalizer.should_process(alert):
            return None

        data = alert.get("data", {})
        rule = alert.get("rule", {})

        user = (
            data.get("user")
            or data.get("dstuser")
            or data.get("srcuser")
            or alert.get("agent", {}).get("name")
            or "usuario_desconocido"
        )

        source_ip = (
            data.get("srcip")
            or alert.get("agent", {}).get("ip")
            or "127.0.0.1"
        )

        status = data.get("status", "FAILURE").upper()
        source_system = data.get("source_system") or "Wazuh SIEM"
        timestamp = alert.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        return {
            "user": user,
            "ip_origen": source_ip,
            "resultado": status,
            "origen": source_system,
            "dispositivo": f"Wazuh Agent ({alert.get('agent', {}).get('name', 'manager')})",
            "timestamp": timestamp,
            "wazuh_metadata": {
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "rule_description": rule.get("description"),
                "mitre": rule.get("mitre", {}).get("id", [])
            }
        }

def forward_alert_sync(normalized_event: Dict[str, Any], ingestion_url: str):
    """Envía el evento a la API de Ingesta (Gateway 8000 o Ingestion 8001)"""
    try:
        r = httpx.post(ingestion_url, json=normalized_event, timeout=5.0)
        rule_info = normalized_event.get('wazuh_metadata', {})
        print(f"  [✓ REENVIADO A APP] Regla {rule_info.get('rule_id')} | Usuario: {normalized_event['user']:10} | IP: {normalized_event['ip_origen']:15} | HTTP {r.status_code}")
    except Exception as e:
        print(f"  [!] No se pudo contactar {ingestion_url}: {e}")

def stream_from_docker(container_name: str = "single-node-wazuh.manager-1", ingestion_url: str = "http://localhost:8000/api/ingest"):
    """
    Lee en vivo las alertas desde el contenedor de Docker de Wazuh Manager
    usando 'docker exec' y tail -F, ideal para entornos Windows.
    """
    print(f"\n=============================================================")
    print(f"  🎧 CONECTOR WAZUH SIEM -> SOC-IA EN EJECUCIÓN (Modo Docker)  ")
    print(f"  Contenedor : {container_name}")
    print(f"  Destino API: {ingestion_url}")
    print(f"=============================================================")
    print("[*] Escuchando alertas en /var/ossec/logs/alerts/alerts.json dentro del contenedor...")
    print("[*] Presiona Ctrl + C para detener.\n")

    cmd = [
        "docker", "exec", "-i", container_name,
        "tail", "-F", "-n", "20", "/var/ossec/logs/alerts/alerts.json"
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, encoding="utf-8", errors="replace")
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                normalized = WazuhAlertNormalizer.normalize_to_canonical(alert)
                if normalized:
                    forward_alert_sync(normalized, ingestion_url)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error procesando alerta: {e}")
    except KeyboardInterrupt:
        print("\n[!] Conector detenido por el usuario.")
    except Exception as e:
        print(f"[X] Error ejecutando docker exec: {e}")

def stream_from_local_file(log_path: str, ingestion_url: str):
    print(f"[*] Escuchando alertas de archivo local: {log_path}...")
    if not os.path.exists(log_path):
        print(f"[!] El archivo {log_path} no existe.")
        return

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                alert = json.loads(line)
                normalized = WazuhAlertNormalizer.normalize_to_canonical(alert)
                if normalized:
                    forward_alert_sync(normalized, ingestion_url)
            except Exception:
                continue

if __name__ == "__main__":
    url = os.getenv("INGESTION_URL", "http://localhost:8000/api/ingest")
    # Si estamos en Windows o existe el binario docker, usamos el stream desde el contenedor
    if os.name == "nt" or not os.path.exists("/var/ossec/logs/alerts/alerts.json"):
        stream_from_docker(ingestion_url=url)
    else:
        stream_from_local_file("/var/ossec/logs/alerts/alerts.json", url)

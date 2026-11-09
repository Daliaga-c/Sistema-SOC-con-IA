import json
import os
import time
# pyrefly: ignore[missing-import]
import httpx
from typing import Optional, Dict, Any

# Lista blanca de reglas enfocadas estrictamente en inicios de sesión anómalos y credenciales
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
    """
    Filtra y normaliza eventos de Wazuh SIEM para alimentar la plataforma SOC-IA.
    Previene tormentas de alertas descartando telemetría no relevante de auditoría.
    """

    @staticmethod
    def should_process(alert: Dict[str, Any]) -> bool:
        """
        Determina si una alerta de Wazuh corresponde a anomalías de autenticación o ataques de credenciales.
        """
        rule = alert.get("rule", {})
        rule_id = str(rule.get("id", ""))
        level = int(rule.get("level", 0))

        # 1. Reglas específicas de login y fuerza bruta
        if rule_id in TARGET_RULE_IDS:
            return True

        # 2. Técnicas MITRE de credenciales
        mitre_ids = rule.get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, str):
            mitre_ids = [mitre_ids]
        if any(m in TARGET_MITRE_TACTICS for m in mitre_ids):
            return True

        # 3. Grupos de autenticación fallida con severidad >= 5
        groups = rule.get("groups", [])
        auth_groups = {"authentication_failed", "authentication_failures", "authentication_anomalies"}
        if any(g in auth_groups for g in groups) and level >= 5:
            return True

        # 4. Datos directos de inicio de sesión con estado FAILURE
        data = alert.get("data", {})
        if data.get("status") == "FAILURE" and level >= 5:
            return True

        return False

    @staticmethod
    def normalize_to_canonical(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Mapea el esquema heterogéneo de Wazuh al formato canónico RawAuthLog de SOC-IA.
        """
        if not WazuhAlertNormalizer.should_process(alert):
            return None

        data = alert.get("data", {})
        rule = alert.get("rule", {})

        # Extraer usuario con cascada de fallbacks
        user = (
            data.get("user")
            or data.get("dstuser")
            or data.get("srcuser")
            or alert.get("agent", {}).get("name")
            or "usuario_desconocido"
        )

        # Extraer IP de origen
        source_ip = (
            data.get("srcip")
            or alert.get("agent", {}).get("ip")
            or "127.0.0.1"
        )

        # Determinar resultado
        status = data.get("status", "FAILURE").upper()

        # Determinar origen del sistema
        source_system = data.get("source_system") or "Wazuh SIEM"

        # Timestamp de la alerta
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


async def forward_alert_to_ingestion(normalized_event: Dict[str, Any], ingestion_url: str = "http://localhost:8001/ingest"):
    """Envía el evento normalizado a la API de Ingesta de SOC-IA"""
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.post(ingestion_url, json=normalized_event)
            print(f" [OK] Alerta enviada a SOC-IA ({r.status_code}): {normalized_event['user']} @ {normalized_event['ip_origen']}")
            return r.json()
        except Exception as e:
            print(f" [!] Error al contactar {ingestion_url}: {e}")
            return None


def stream_wazuh_log_file(log_path: str, ingestion_url: str = "http://localhost:8001/ingest"):
    """
    Monitorea en tiempo real el archivo /var/ossec/logs/alerts/alerts.json de Wazuh
    y procesa únicamente las alertas relevantes sin saturar el sistema.
    """
    import asyncio

    if not os.path.exists(log_path):
        print(f" [Aviso] El archivo {log_path} aún no existe. Esperando a que Wazuh lo genere...")
        return

    print(f"[*] Escuchando alertas de Wazuh en {log_path}...")
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        # Ir al final del archivo para procesar únicamente eventos nuevos
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
                    asyncio.run(forward_alert_to_ingestion(normalized, ingestion_url))
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error procesando línea: {e}")

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else "/var/ossec/logs/alerts/alerts.json"
    stream_wazuh_log_file(log_file)

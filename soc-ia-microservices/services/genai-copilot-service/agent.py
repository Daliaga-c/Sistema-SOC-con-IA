"""
SOC Copilot - Agente Conversacional Especializado en Ciberseguridad.
Soporta RAG sobre NIST SP 800-61 y MITRE ATT&CK con capacidad de Function Calling y Human-in-the-loop.
"""
from typing import Dict, Any, List
import os
import json

# Base de conocimiento RAG en memoria (NIST y MITRE)
KNOWLEDGE_BASE = {
    "T1110": {
        "title": "T1110 - Brute Force (Fuerza Bruta)",
        "tactics": ["Credential Access"],
        "description": "Los adversarios intentan obtener acceso sistemático probando combinaciones de contraseñas contra cuentas específicas o listas de usuarios comunes.",
        "mitigation": "1. Bloquear IP de origen temporalmente en firewall/Active Response.\n2. Habilitar bloqueo temporal de cuenta tras 5 intentos fallidos.\n3. Exigir autenticación multifactor (MFA)."
    },
    "T1078": {
        "title": "T1078 - Valid Accounts (Cuentas Válidas)",
        "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        "description": "El atacante utiliza credenciales legítimas de un usuario corporativo o cuenta de servicio, comúnmente fuera de horario laboral o desde geolocalizaciones anómalas.",
        "mitigation": "1. Notificar al usuario para confirmar si reconoce la actividad.\n2. Revocar tokens de sesión activos de inmediato.\n3. Forzar cambio de contraseña preventivo."
    },
    "NIST_INCIDENT_LIFECYCLE": {
        "title": "Guía de Respuesta a Incidentes NIST SP 800-61 Rev 2",
        "phases": [
            "1. Preparación",
            "2. Detección y Análisis (Triaje con IA)",
            "3. Contención, Erradicación y Recuperación (Mitigación asistida con aprobación humana)",
            "4. Actividad Post-Incidente (Lecciones aprendidas y Active Learning)"
        ]
    }
}

class SOCCopilotAgent:
    def __init__(self):
        self.system_prompt = (
            "Eres el Asistente Senior de Ciberseguridad (SOC Copilot) de la organización. "
            "Tu objetivo es ayudar al analista en el triaje rápido, explicación de alertas con base en MITRE ATT&CK / NIST "
            "y formulación de recomendaciones de contención. Mantén siempre una postura de Human-in-the-loop: "
            "nunca ejecutes acciones irreversibles de bloqueo sin solicitar la aprobación humana expresa del operador."
        )

    def analyze_alert(self, alert_data: Dict[str, Any], query: str) -> Dict[str, Any]:
        """
        Genera el razonamiento y respuesta estructurada para una alerta investigada.
        """
        ip = alert_data.get("raw_event", {}).get("source_ip", "Desconocida")
        user = alert_data.get("raw_event", {}).get("user", "Desconocido")
        source = alert_data.get("raw_event", {}).get("source_system", "Web")
        risk_score = alert_data.get("ml_score", {}).get("risk_score", 50.0)
        mitre_list = alert_data.get("mitre_attack", ["T1110 - Brute Force"])

        # Recuperación de RAG
        rag_context = KNOWLEDGE_BASE.get("T1110") if "1110" in str(mitre_list) else KNOWLEDGE_BASE.get("T1078")

        response_text = (
            f"### 🛡️ Diagnóstico del Asistente SOC (Copilot)\n\n"
            f"**Resumen de Investigación:**\n"
            f"Se ha detectado una anomalía crítica en el canal **{source}** para la cuenta `{user}` desde la dirección IP `{ip}`. "
            f"El modelo de Machine Learning le ha asignado un **Score de Riesgo de {risk_score}/100** debido a patrones de comportamiento sospechosos.\n\n"
            f"**Técnica MITRE ATT&CK Mapeada:**\n"
            f"- **{rag_context['title']}**\n"
            f"- *Detalle Forense:* {rag_context['description']}\n\n"
            f"**Protocolo de Contención Asistida (NIST SP 800-61):**\n"
            f"{rag_context['mitigation']}\n\n"
            f"⚠️ **Control de Gobernanza (Human-in-the-Loop):**\n"
            f"¿Deseas que prepare la orden de **Active Response en Wazuh** para bloquear la IP `{ip}` por 3600 segundos?"
        )

        return {
            "reply": response_text,
            "recommended_action": "BLOCK_IP",
            "target": ip,
            "requires_human_approval": True,
            "mitre_details": rag_context
        }

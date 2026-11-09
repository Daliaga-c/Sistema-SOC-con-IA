"""
SOC Copilot - Agente Conversacional Especializado en Ciberseguridad.
Soporta RAG sobre NIST SP 800-61 y MITRE ATT&CK con capa local de vector store.
"""
from typing import Any, Dict, List

from rag_store import ensure_default_index


class SOCCopilotAgent:
    def __init__(self):
        self.system_prompt = (
            "Eres el Asistente Senior de Ciberseguridad (SOC Copilot) de la organización. "
            "Tu objetivo es ayudar al analista en el triaje rápido, explicación de alertas con base en MITRE ATT&CK / NIST "
            "y formulación de recomendaciones de contención. Mantén siempre una postura de Human-in-the-loop: "
            "nunca ejecutes acciones irreversibles de bloqueo sin solicitar la aprobación humana expresa del operador."
        )
        self.rag_store = ensure_default_index('./chroma_db')

    def _retrieve_context(self, query: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        if not query:
            query = ""

        event_context = alert_data.get("raw_event", {}) if isinstance(alert_data, dict) else {}
        user = event_context.get("user", "usuario")
        ip = event_context.get("source_ip", "IP desconocida")
        source = event_context.get("source_system", "sistema")

        query_text = f"{query} {source} {user} {ip} {alert_data.get('title', '')}"
        matches = self.rag_store.search(query_text, limit=3)

        if not matches:
            return {
                "title": "Guías NIST/MITRE",
                "description": "Se recomienda revisar el ciclo de respuesta a incidentes y validar la actividad con aprobación humana.",
                "mitigation": "1. Validar la actividad con el usuario.\n2. Revisión de sesión activa.\n3. Bloqueo controlado y documentado.",
                "sources": [],
            }

        best = matches[0][0]
        context = {
            "title": best.metadata.get('technique') or best.metadata.get('source', 'Guía de referencia'),
            "description": best.content,
            "mitigation": "1. Aislar la cuenta o IP sospechosa.\n2. Validar la actividad con el analista.\n3. Aplicar bloqueo por Active Response con aprobación humana.",
            "sources": [item[0].metadata for item in matches],
        }
        return context

    def analyze_alert(self, alert_data: Dict[str, Any], query: str) -> Dict[str, Any]:
        """Genera el razonamiento y respuesta estructurada para una alerta investigada."""
        ip = alert_data.get("raw_event", {}).get("source_ip", "Desconocida")
        user = alert_data.get("raw_event", {}).get("user", "Desconocido")
        source = alert_data.get("raw_event", {}).get("source_system", "Web")
        risk_score = alert_data.get("ml_score", {}).get("risk_score", 50.0)
        mitre_list = alert_data.get("mitre_attack", ["T1110 - Brute Force"])

        rag_context = self._retrieve_context(query or "anomalía de autenticación", alert_data)
        technique_label = "T1110 - Brute Force" if "1110" in str(mitre_list) else "T1078 - Valid Accounts"

        response_text = (
            f"### 🛡️ Diagnóstico del Asistente SOC (Copilot)\n\n"
            f"**Resumen de Investigación:**\n"
            f"Se ha detectado una anomalía crítica en el canal **{source}** para la cuenta `{user}` desde la dirección IP `{ip}`. "
            f"El modelo de Machine Learning le ha asignado un **Score de Riesgo de {risk_score}/100** debido a patrones de comportamiento sospechosos.\n\n"
            f"**Técnica MITRE ATT&CK Mapeada:**\n"
            f"- **{technique_label}**\n"
            f"- *Detalle Forense:* {rag_context['description']}\n\n"
            f"**Protocolo de Contención Asistida (NIST SP 800-61):**\n"
            f"{rag_context['mitigation']}\n\n"
            f"⚠️ **Control de Gobernanza (Human-in-the-loop):**\n"
            f"¿Deseas que prepare la orden de **Active Response en Wazuh** para bloquear la IP `{ip}` por 3600 segundos?"
        )

        return {
            "reply": response_text,
            "recommended_action": "BLOCK_IP",
            "target": ip,
            "requires_human_approval": True,
            "mitre_details": rag_context,
            "retrieved_documents": rag_context.get('sources', []),
        }

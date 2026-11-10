"""
SOC Copilot - Agente Conversacional Especializado en Ciberseguridad.
Soporta RAG sobre NIST SP 800-61 y MITRE ATT&CK con capa local de vector store.
"""
import json
import os
from typing import Any, Dict

import httpx

from rag_store import ensure_default_index


class SOCCopilotAgent:
    def __init__(self):
        self.ollama_base_url = os.getenv(
            "OLLAMA_BASE_URL", "http://host.docker.internal:11434"
        ).rstrip("/")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
        self.system_prompt = (
            "Eres el Asistente Senior de Ciberseguridad (SOC Copilot) de la organización. "
            "Tu objetivo es ayudar al analista en el triaje rápido, explicación de alertas con base en MITRE ATT&CK / NIST "
            "y formulación de recomendaciones de contención. Mantén siempre una postura de Human-in-the-loop: "
            "nunca ejecutes acciones irreversibles de bloqueo sin solicitar la aprobación humana expresa del operador. "
            "Usa el contexto NIST/MITRE proporcionado, distingue hechos de hipótesis y responde en español."
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

    async def _ask_ollama(self, query: str, prompt_context: Dict[str, Any]) -> str:
        async with httpx.AsyncClient(timeout=90.0) as client:
            response = await client.post(
                f"{self.ollama_base_url}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": [
                        {"role": "system", "content": self.system_prompt},
                        {
                            "role": "user",
                            "content": (
                                f"Pregunta del analista: {query}\n\n"
                                f"Contexto RAG NIST/MITRE y alerta (JSON): "
                                f"{json.dumps(prompt_context, ensure_ascii=False, default=str)}"
                            ),
                        },
                    ],
                    "stream": False,
                },
            )
            response.raise_for_status()

        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Ollama devolvió una respuesta con formato inválido.")
        message = payload.get("message")
        reply = message.get("content") if isinstance(message, dict) else None
        if not isinstance(reply, str) or not reply.strip():
            raise ValueError("Ollama devolvió una respuesta vacía o con formato inválido.")
        return reply.strip()

    async def respond(
        self,
        query: str,
        alert_data: Dict[str, Any] | None = None,
        analyst_name: str = "Analista SOC N1",
    ) -> Dict[str, Any]:
        """Responde al analista con Ollama y el contexto relevante del RAG."""
        alert_data = alert_data or {}
        rag_context = self._retrieve_context(query, alert_data)
        prompt_context = {
            "analista": analyst_name,
            "alerta": alert_data or None,
            "referencias": rag_context,
        }
        reply = await self._ask_ollama(query, prompt_context)

        result = {
            "reply": reply,
            "recommended_action": None,
            "requires_human_approval": False,
            "mitre_details": rag_context,
            "retrieved_documents": rag_context.get("sources", []),
        }

        if alert_data:
            raw_event = alert_data.get("raw_event")
            ip = (
                raw_event.get("source_ip", "Desconocida")
                if isinstance(raw_event, dict)
                else "Desconocida"
            )
            result.update({
                "recommended_action": "BLOCK_IP",
                "target": ip,
                "requires_human_approval": True,
            })

        return result

    async def analyze_alert(self, alert_data: Dict[str, Any], query: str) -> Dict[str, Any]:
        """Mantiene la interfaz de análisis de alertas para los consumidores existentes."""
        return await self.respond(query, alert_data)

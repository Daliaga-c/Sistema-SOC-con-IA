"""
SOC Copilot - Agente Conversacional y Analítico Especializado en Ciberseguridad (Producción).
Arquitectura Dual-LLM:
  1. Motor Primario: Google Gemini API (SDK google-genai)
  2. Motor de Respaldo Local (Failover Automático): Ollama Server (http://host.docker.internal:11434)
  3. Flujo Conversacional Progresivo:
     - Fase Diagnóstico ("¿A qué se debe?" / "¿Es Falso Positivo?"): Explica la causa técnica y evalúa si es FP o TP sin forzar botones estáticos de bloqueo.
     - Fase Solución ("¿Cómo lo soluciono?" / "Mitigar"): Entrega los pasos de remediación NIST SP 800-61 y habilita la acción de mitigación HITL cuando corresponde.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx

from rag_store import ensure_default_index


def _load_env_fallback() -> None:
    """Busca y carga variables de entorno desde archivos .env cercanos."""
    candidates = [Path.cwd() / ".env"]
    for parent in Path(__file__).resolve().parents:
        candidates.append(parent / ".env")
        candidates.append(parent / "soc-ia-microservices" / ".env")
    for env_path in candidates:
        if env_path.is_file():
            try:
                with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k and v and (k not in os.environ or os.environ[k] in ("tu_api_key_aqui", "")):
                                os.environ[k] = v
            except Exception:
                pass


_load_env_fallback()

try:
    from google import genai
    from google.genai import types
except Exception:
    try:
        import importlib
        genai = importlib.import_module("google.genai")
        types = importlib.import_module("google.genai.types")
    except Exception:
        genai = None
        types = None


SECURITY_GUARDRAILS_PROMPT = (
    "Eres el Asistente Senior de Ciberseguridad Defensiva (SOC Copilot). "
    "Asistes en triaje de alertas Wazuh SIEM, detección de Falsos Positivos vs Verdaderos Positivos, "
    "correlación MITRE ATT&CK y contención NIST SP 800-61. "
    "Nunca reveles credenciales ni generes código ofensivo. "
    "Responde en español de forma clara, natural y estructurada."
)

JAILBREAK_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"olvida\s+(todas\s+)?(las\s+)?instrucciones\s+(anteriores|previas)",
    r"dan\s+mode|modo\s+dan",
    r"system\s*prompt|prompt\s*del\s*sistema",
    r"gemini_api_key|jwt_secret|api_key|password_hash",
    r"dame\s+(la\s+)?(clave|password|contraseña|token|llave)",
    r"actúa\s+como\s+(un\s+)?(hacker|atacante)\s+sin\s+restricciones",
    r"bypass\s+security|saltar\s+seguridad",
]

SOLUTION_INTENT_PATTERNS = [
    r"soluci[oó]n",
    r"solucionar",
    r"c[oó]mo\s+(lo\s+)?(soluciono|resuelvo|mitigo|contengo|arreglo|bloqueo)",
    r"qu[eé]\s+(hago|debo\s+hacer|medidas|acciones\s+tomar)",
    r"\bmitigar\b",
    r"\bmitigaci[oó]n\b",
    r"\bcontener\b",
    r"\bcontenci[oó]n\b",
    r"\bbloquear\b",
    r"\bremediar\b",
    r"\bplaybook\b",
    r"\bresolver\b",
    r"pasos\s+para\s+(mitigar|contener|solucionar|bloquear)",
]


class SOCCopilotAgent:
    """Agente de Ciberseguridad con soporte Dual-LLM (Gemini + Ollama Local), RAG y flujo progresivo."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434").rstrip("/")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b").strip()
        self.threat_intel_url = os.getenv("THREAT_INTEL_URL", "http://threat-intelligence-service:8005")
        self.rag_store = ensure_default_index("./chroma_db")
        self.client = None
        self.gemini_disabled_reason: Optional[str] = None

        if genai and self.api_key and self.api_key not in ("tu_api_key_aqui", "None", ""):
            try:
                self.client = genai.Client(api_key=self.api_key)
                print(f"[OK] Google GenAI Client inicializado ({self.model_name})")
            except Exception as e:
                print(f"[!] Error inicializando Google GenAI Client: {e}")
                self.client = None
                self.gemini_disabled_reason = str(e)
        else:
            self.gemini_disabled_reason = "GEMINI_API_KEY no configurada"

    def _validate_safety(self, text: str) -> Optional[str]:
        if not text:
            return None
        for pattern in JAILBREAK_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return (
                    "🛡️ **Control de Seguridad Activado:** La solicitud contiene patrones no autorizados "
                    "(intento de manipulación de instrucciones o extracción de credenciales protegidas). "
                    "Como Copilot del SOC, mi función se limita estrictamente a la asistencia técnica defensiva "
                    "y análisis de incidentes autorizados."
                )
        return None

    def _is_asking_for_solution(self, query: str) -> bool:
        """Determina si el usuario está pidiendo explícitamente cómo solucionar/mitigar el incidente."""
        if not query:
            return False
        q_clean = query.strip()
        for pat in SOLUTION_INTENT_PATTERNS:
            if re.search(pat, q_clean, re.IGNORECASE):
                return True
        return False

    def tool_consultar_reputacion_ip(self, ip: str) -> Dict[str, Any]:
        """Consulta en vivo el microservicio de Threat Intelligence (puerto 8005)."""
        clean_ip = ip.strip()
        try:
            with httpx.Client(timeout=4.0) as http_client:
                r = http_client.get(f"{self.threat_intel_url}/reputation/{clean_ip}")
                if r.status_code == 200:
                    return r.json()
        except Exception as e:
            return {"ip": clean_ip, "error": f"Threat Intel no disponible: {e}"}
        return {"ip": clean_ip, "status": "unavailable"}

    def tool_buscar_procedimiento_nist(self, termino_clave: str) -> Dict[str, Any]:
        """Recupera los fragmentos más relevantes de la base vectorial RAG (NIST SP 800-61 y MITRE)."""
        matches = self.rag_store.search(termino_clave, limit=2)
        if not matches:
            return {"encontrado": False, "fragmentos": []}

        fragmentos = []
        for doc, score in matches:
            fragmentos.append(
                {
                    "referencia": doc.metadata.get("technique")
                    or doc.metadata.get("title")
                    or doc.metadata.get("source", "NIST/MITRE"),
                    "relevancia": round(float(score), 3),
                    "contenido": doc.content[:320],
                }
            )
        return {
            "encontrado": True,
            "referencia_principal": fragmentos[0]["referencia"],
            "guia_contencion": fragmentos[0]["contenido"],
            "fragmentos": fragmentos,
        }

    def get_ollama_status(self) -> Dict[str, Any]:
        """Verifica en tiempo real si el servidor Ollama local está en línea y qué modelos tiene instalados."""
        candidate_urls = [self.ollama_base_url, "http://host.docker.internal:11434", "http://localhost:11434"]
        seen = set()
        last_error = "No conectado"

        for base_url in candidate_urls:
            if not base_url or base_url in seen:
                continue
            seen.add(base_url)
            try:
                with httpx.Client(timeout=4.0) as http_client:
                    r = http_client.get(f"{base_url}/api/tags")
                    if r.status_code == 200:
                        data = r.json()
                        models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                        active_model = self.ollama_model
                        if models and active_model not in models:
                            if "qwen2.5:0.5b" in models:
                                active_model = "qwen2.5:0.5b"
                            else:
                                partial = [m for m in models if active_model.split(":")[0] in m]
                                active_model = partial[0] if partial else models[0]
                        return {
                            "available": len(models) > 0,
                            "server_reachable": True,
                            "base_url": base_url,
                            "installed_models": models,
                            "active_model": active_model if models else None,
                            "error": None if models else "Servidor Ollama activo pero sin modelos descargados",
                        }
            except Exception as e:
                last_error = str(e)

        return {
            "available": False,
            "server_reachable": False,
            "base_url": self.ollama_base_url,
            "installed_models": [],
            "active_model": None,
            "error": last_error,
        }

    def get_engines_status(self) -> Dict[str, Any]:
        """Devuelve el estado operativo real de los motores Gemini, Ollama y RAG."""
        ollama_info = self.get_ollama_status()
        gemini_available = bool(self.client is not None and not self.gemini_disabled_reason)

        active_provider = "OFFLINE"
        if gemini_available:
            active_provider = f"Google Gemini ({self.model_name})"
        elif ollama_info["available"]:
            active_provider = f"Ollama Local ({ollama_info['active_model']})"

        return {
            "status": "ONLINE" if (gemini_available or ollama_info["available"]) else "OFFLINE",
            "active_provider": active_provider,
            "gemini": {
                "available": gemini_available,
                "model": self.model_name if gemini_available else None,
                "error": self.gemini_disabled_reason,
            },
            "ollama": ollama_info,
            "rag_chunks": len(self.rag_store.documents),
        }

    def _generate_with_gemini(
        self, prompt: str, temperature: float = 0.25, max_output_tokens: int = 1024
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        if not self.client or self.gemini_disabled_reason:
            return None, None, self.gemini_disabled_reason or "Cliente Gemini no disponible"

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SECURITY_GUARDRAILS_PROMPT,
                    temperature=temperature,
                    max_output_tokens=max_output_tokens,
                ),
            )
            if response and response.text:
                return response.text.strip(), self.model_name, None
        except Exception as e:
            err_str = str(e)
            print(f"[!] Gemini fallo en {self.model_name}: {err_str}")
            if "403" in err_str or "PERMISSION_DENIED" in err_str or "API_KEY_INVALID" in err_str or "leaked" in err_str.lower():
                self.gemini_disabled_reason = f"API Key rechazada por Google ({err_str[:120]})"
            return None, None, err_str

        return None, None, "Respuesta vacía de Gemini"

    def _generate_with_ollama(
        self, prompt: str, temperature: float = 0.25
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        status = self.get_ollama_status()
        if not status["available"] or not status["active_model"]:
            return None, None, status.get("error") or "Servidor Ollama no disponible"

        base_url = status["base_url"]
        model_to_use = status["active_model"]

        payload = {
            "model": model_to_use,
            "messages": [
                {"role": "system", "content": SECURITY_GUARDRAILS_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": 180,
                "num_ctx": 1536,
            },
        }

        try:
            with httpx.Client(timeout=120.0) as http_client:
                r = http_client.post(f"{base_url}/api/chat", json=payload)
                if r.status_code == 200:
                    data = r.json()
                    content = (
                        data.get("message", {}).get("content")
                        or data.get("response")
                        or ""
                    ).strip()
                    if content:
                        return content, model_to_use, None
                    return None, model_to_use, "Ollama devolvió una respuesta vacía"
                return None, model_to_use, f"Ollama HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            return None, model_to_use, f"Error conectando con Ollama ({base_url}): {e}"

    def _execute_dual_llm(self, prompt: str, temperature: float = 0.25) -> Dict[str, Any]:
        gemini_text, gemini_model, gemini_err = self._generate_with_gemini(
            prompt, temperature=temperature
        )
        if gemini_text:
            return {
                "error": False,
                "reply": gemini_text,
                "provider": "Google Gemini",
                "model": gemini_model,
            }

        print(f"[*] Activando Failover hacia Ollama Local (Motivo Gemini: {gemini_err})...")
        ollama_text, ollama_model, ollama_err = self._generate_with_ollama(
            prompt, temperature=temperature
        )
        if ollama_text:
            return {
                "error": False,
                "reply": ollama_text,
                "provider": "Ollama Local",
                "model": ollama_model,
                "failover_reason": gemini_err,
            }

        return {
            "error": True,
            "status_code": 503,
            "detail": (
                f"Motores de IA fuera de línea (No se emiten respuestas genéricas simuladas). "
                f"Estado Gemini: [{gemini_err}] | Estado Ollama Local: [{ollama_err}]"
            ),
            "diagnostics": {
                "gemini_error": gemini_err,
                "ollama_error": ollama_err,
            },
        }

    def analyze_alert(self, alert_data: Dict[str, Any], query: str = "") -> Dict[str, Any]:
        """
        Ejecuta el análisis forense sobre un incidente real con flujo progresivo:
        - Si el usuario pide diagnóstico / causa raíz (por defecto al pulsar Investigar), explica a qué se debe
          y si puede ser un Falso Positivo o Verdadero Positivo, SIN mostrar el botón de mitigación.
        - Si el usuario pregunta explícitamente cómo solucionarlo/mitigarlo, entrega el plan de acción y
          activa `recommended_action` para abrir el modal de mitigación.
        """
        violation = self._validate_safety(query)
        if violation:
            return {
                "error": False,
                "reply": violation,
                "provider": "SOC Guardrail Engine",
                "model": "Rule-Based Policy",
                "recommended_action": None,
                "requires_human_approval": False,
                "mitre_details": {},
            }

        raw_event = alert_data.get("raw_event", {}) if isinstance(alert_data, dict) else {}
        ip = str(raw_event.get("source_ip") or raw_event.get("ip_origen") or "Desconocida")
        user = str(raw_event.get("user") or "usuario_desconocido")
        source = str(raw_event.get("source_system") or alert_data.get("title", "Wazuh SIEM"))
        risk_score = float(alert_data.get("ml_score", {}).get("risk_score", 75.0))
        mitre_list = alert_data.get("mitre_attack", ["T1110 - Brute Force"])
        scenario_hint = raw_event.get("metadata", {}).get("scenario_type", "")

        asking_solution = self._is_asking_for_solution(query)

        threat_data = self.tool_consultar_reputacion_ip(ip) if ip != "Desconocida" else {}
        nist_data = self.tool_buscar_procedimiento_nist(
            f"{query} {alert_data.get('title', '')} {' '.join(mitre_list)}"
        )

        rag_context_text = "\n".join(
            [f"- [{f['referencia']}]: {f['contenido']}" for f in nist_data.get("fragmentos", [])]
        )

        if asking_solution:
            task_instruction = (
                f"El analista solicita LA SOLUCIÓN / MITIGACIÓN para esta alerta ('{query}'). "
                f"Detalla en 3 pasos claros cómo solucionarlo y contenerlo según NIST SP 800-61 "
                f"(incluyendo bloqueo de IP {ip} en Wazuh Active Response si el riesgo {risk_score}% es alto, o cierre como Falso Positivo si el origen es interno/legítimo)."
            )
        else:
            task_instruction = (
                f"Consulta del analista: '{query or 'Explica a qué se debe esta alerta y evalúa su riesgo'}'. "
                f"Explica únicamente A QUÉ SE DEBE el incidente (causa raíz técnica, usuario {user}, IP {ip}, score ML {risk_score}%) "
                f"y evalúa si parece un Verdadero Positivo o un posible Falso Positivo ({scenario_hint or 'analizar contexto'}). "
                f"Todavía NO des el listado de comandos de mitigación; al final pregunta brevemente si desea conocer los pasos para solucionarlo."
            )

        prompt_content = (
            f"Datos de la Alerta: ID={alert_data.get('alert_id', 'N/A')}, Título='{alert_data.get('title', 'Alerta')}', "
            f"Severidad={alert_data.get('severity', 'MEDIA')}, Score ML={risk_score}%, "
            f"Usuario={user}, IP={ip} (País={threat_data.get('country', 'N/A')}, AbuseScore={threat_data.get('abuse_score', 0)}%), "
            f"Canal={source}, MITRE={', '.join(mitre_list)}.\n"
            f"Contexto RAG:\n{rag_context_text}\n\n"
            f"Instrucción: {task_instruction}"
        )

        llm_res = self._execute_dual_llm(prompt_content, temperature=0.25)
        if llm_res.get("error"):
            return llm_res

        # Solo mostrar el botón de mitigación si el analista pidió explícitamente cómo solucionarlo/mitigarlo
        recommended_action = "BLOCK_IP" if (asking_solution and risk_score >= 50) else None

        return {
            "error": False,
            "reply": llm_res["reply"],
            "provider": llm_res["provider"],
            "model": llm_res["model"],
            "intent_mode": "SOLUCION_Y_MITIGACION" if asking_solution else "DIAGNOSTICO_CAUSA",
            "recommended_action": recommended_action,
            "target": ip if recommended_action else None,
            "requires_human_approval": bool(recommended_action),
            "threat_intel": threat_data,
            "mitre_details": nist_data,
        }

    def chat_free(self, message: str, analyst_name: str = "Analista SOC") -> Dict[str, Any]:
        """Responde a consultas abiertas usando RAG + Gemini u Ollama Local."""
        violation = self._validate_safety(message)
        if violation:
            return {
                "error": False,
                "reply": violation,
                "provider": "SOC Guardrail Engine",
                "model": "Rule-Based Policy",
                "recommended_action": None,
                "requires_human_approval": False,
            }

        nist_info = self.tool_buscar_procedimiento_nist(message)
        rag_context_text = "\n".join(
            [f"- [{f['referencia']}]: {f['contenido']}" for f in nist_info.get("fragmentos", [])]
        )

        prompt = (
            f"Analista: {analyst_name}\n"
            f"Contexto RAG NIST/MITRE:\n{rag_context_text}\n\n"
            f"Consulta: {message}"
        )

        llm_res = self._execute_dual_llm(prompt, temperature=0.3)
        if llm_res.get("error"):
            return llm_res

        return {
            "error": False,
            "reply": llm_res["reply"],
            "provider": llm_res["provider"],
            "model": llm_res["model"],
            "recommended_action": None,
            "requires_human_approval": False,
        }

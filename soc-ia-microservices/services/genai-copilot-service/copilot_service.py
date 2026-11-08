from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from agent import SOCCopilotAgent

app = FastAPI(title="SOC-IA GenAI Copilot Service", version="1.0.0")
copilot = SOCCopilotAgent()

class ChatRequest(BaseModel):
    message: str
    alert_context: Optional[Dict[str, Any]] = None
    analyst_name: Optional[str] = "Analista SOC N1"

@app.post("/chat")
async def chat(request: ChatRequest):
    if request.alert_context:
        result = copilot.analyze_alert(request.alert_context, request.message)
    else:
        # Respuesta libre a consultas de seguridad y procedimientos
        result = {
            "reply": (
                f"Hola {request.analyst_name}. Estoy conectado a las fuentes de Wazuh y al Feature Store de ML. "
                "Para iniciar un análisis forense guiado, puedes seleccionar una alerta de la tabla y presionar "
                "**'Investigar con IA'** o preguntarme sobre cualquier técnica del framework MITRE ATT&CK."
            ),
            "recommended_action": None,
            "requires_human_approval": False
        }
    return result

@app.get("/health")
async def health():
    return {"status": "UP", "service": "genai-copilot-service"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("copilot_service:app", host="0.0.0.0", port=8004, reload=True)

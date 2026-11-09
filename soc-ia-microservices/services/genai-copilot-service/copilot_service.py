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
        # Respuesta dinámica o consulta de ciberseguridad con Gemini y guardrails
        result = copilot.chat_free(request.message, request.analyst_name or "Analista SOC N1")
    return result

@app.get("/health")
async def health():
    return {"status": "UP", "service": "genai-copilot-service"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("copilot_service:app", host="0.0.0.0", port=8004, reload=True)

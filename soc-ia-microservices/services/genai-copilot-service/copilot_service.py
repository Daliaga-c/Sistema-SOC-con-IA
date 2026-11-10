from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent import SOCCopilotAgent

app = FastAPI(
    title="SOC-IA GenAI Copilot Service (Gemini + Ollama Local Failover)",
    version="3.0.0",
)
copilot = SOCCopilotAgent()


class ChatRequest(BaseModel):
    message: str
    alert_context: Optional[Dict[str, Any]] = None
    analyst_name: Optional[str] = "Analista SOC"


@app.post("/chat")
async def chat(request: ChatRequest):
    if request.alert_context:
        result = copilot.analyze_alert(request.alert_context, request.message)
    else:
        result = copilot.chat_free(
            request.message, request.analyst_name or "Analista SOC"
        )

    if result.get("error"):
        raise HTTPException(
            status_code=result.get("status_code", 503),
            detail=result.get("detail", "Motores de IA (Gemini y Ollama) fuera de línea"),
        )
    return result


@app.get("/status")
async def get_status():
    return copilot.get_engines_status()


@app.get("/health")
async def health():
    status = copilot.get_engines_status()
    return {
        "status": "UP",
        "service": "genai-copilot-service",
        "engines": status,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("copilot_service:app", host="0.0.0.0", port=8004, reload=True)

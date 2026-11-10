import httpx
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
    try:
        return await copilot.respond(
            request.message,
            request.alert_context,
            request.analyst_name or "Analista SOC N1",
        )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Ollama no respondió dentro del tiempo esperado.") from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Ollama respondió con estado HTTP {exc.response.status_code}.",
        ) from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="No fue posible conectar con Ollama.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

@app.get("/health")
async def health():
    return {"status": "UP", "service": "genai-copilot-service"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("copilot_service:app", host="0.0.0.0", port=8004, reload=True)

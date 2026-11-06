from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
import httpx
import os
from pathlib import Path

app = FastAPI(
    title="SOC-IA API Gateway",
    description="Puerta de enlace perimetral y orquestadora de los microservicios del Centro de Operaciones de Seguridad",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# URLs de los microservicios internos
INGESTION_URL = os.getenv("INGESTION_SERVICE_URL", "http://ingestion-service:8001")
ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml-anomaly-detection:8002")
ALERTS_URL = os.getenv("ALERTS_SERVICE_URL", "http://alerts-incidents-service:8003")
COPILOT_URL = os.getenv("COPILOT_SERVICE_URL", "http://genai-copilot-service:8004")
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "http://threat-intelligence-service:8005")

# Montaje de archivos estáticos y hojas de estilo de la consola del analista
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "analyst-console"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    css_dir = FRONTEND_DIR / "css"
    if css_dir.exists():
        app.mount("/css", StaticFiles(directory=str(css_dir)), name="css")

@app.get("/")
async def root():
    dashboard_path = FRONTEND_DIR / "analyst_dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))
    return {"message": "SOC-IA API Gateway activo y operando", "docs": "/docs"}

@app.get("/login")
async def login_page():
    login_path = FRONTEND_DIR / "analyst_login.html"
    if login_path.exists():
        return FileResponse(str(login_path))
    return {"message": "Login page not found"}

@app.get("/health")
async def health_check():
    return {
        "gateway": "UP",
        "services": {
            "ingestion": INGESTION_URL,
            "ml_anomaly": ML_SERVICE_URL,
            "alerts": ALERTS_URL,
            "copilot": COPILOT_URL,
            "threat_intel": THREAT_INTEL_URL
        }
    }

# Proxy hacia microservicio de Alertas e Incidentes
@app.get("/api/alerts")
async def get_alerts():
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.get(f"{ALERTS_URL}/alerts")
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as e:
            return JSONResponse(status_code=503, content={"error": "Alerts service unavailable", "details": str(e)})

@app.post("/api/alerts/{alert_id}/mitigate")
async def mitigate_alert(alert_id: str, request: Request):
    body = await request.json()
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{ALERTS_URL}/alerts/{alert_id}/mitigate", json=body)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as e:
            return JSONResponse(status_code=503, content={"error": "Alerts service unavailable", "details": str(e)})

# Proxy hacia microservicio de Inferencia de ML
@app.post("/api/predict")
async def predict_anomaly(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{ML_SERVICE_URL}/predict", json=payload)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as e:
            return JSONResponse(status_code=503, content={"error": "ML Service unavailable", "details": str(e)})

# Proxy hacia microservicio de Asistente IA (Chatbot Copilot)
@app.post("/api/chat")
async def chat_with_copilot(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            r = await client.post(f"{COPILOT_URL}/chat", json=payload)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as e:
            return JSONResponse(status_code=503, content={"error": "Copilot Service unavailable", "details": str(e)})

# Proxy hacia microservicio de Ingesta
@app.post("/api/ingest")
async def ingest_event(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{INGESTION_URL}/ingest", json=payload)
            return JSONResponse(status_code=r.status_code, content=r.json())
        except Exception as e:
            return JSONResponse(status_code=503, content={"error": "Ingestion service unavailable", "details": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway_service:app", host="0.0.0.0", port=8000, reload=True)

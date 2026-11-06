from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any, Optional
from model import AnomalyDetector

app = FastAPI(title="SOC-IA ML Anomaly Detection Service", version="1.0.0")
detector = AnomalyDetector()

class EventPayload(BaseModel):
    event_id: Optional[str] = "EVT-TEST"
    timestamp: Optional[str] = None
    source_system: Optional[str] = "Portal Web Dummy"
    user: str
    source_ip: str
    status: str
    metadata: Optional[Dict[str, Any]] = None

@app.post("/predict")
async def predict_risk(event: EventPayload):
    result = detector.predict(event.dict())
    return {
        "event_id": event.event_id,
        **result
    }

@app.get("/health")
async def health():
    return {"status": "UP", "service": "ml-anomaly-detection", "version": detector.version}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("anomaly_detection_service:app", host="0.0.0.0", port=8002, reload=True)

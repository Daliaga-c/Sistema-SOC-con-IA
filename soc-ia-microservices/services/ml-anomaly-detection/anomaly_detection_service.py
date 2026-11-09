import hmac
import os

from fastapi import FastAPI
from fastapi import Header, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Literal, Optional
from model import AnomalyDetector
from train import train_from_feedback

app = FastAPI(title="SOC-IA ML Anomaly Detection Service", version="1.0.0")
detector = AnomalyDetector()
ACTIVE_LEARNING_TOKEN = os.getenv("ACTIVE_LEARNING_TOKEN", "")

class EventPayload(BaseModel):
    event_id: Optional[str] = "EVT-TEST"
    timestamp: Optional[str] = None
    source_system: Optional[str] = "Portal Web Dummy"
    user: str
    source_ip: str
    status: str
    metadata: Optional[Dict[str, Any]] = None


class FeedbackTrainingRecord(BaseModel):
    alert_id: str
    label: Literal["VERDADERO_POSITIVO", "FALSO_POSITIVO"]
    event: Dict[str, Any]


class RetrainingRequest(BaseModel):
    records: List[FeedbackTrainingRecord]


@app.post("/predict")
async def predict_risk(event: EventPayload):
    result = detector.predict(event.dict())
    return {
        "event_id": event.event_id,
        **result
    }


@app.post("/retrain")
async def retrain_from_analyst_feedback(
    request: RetrainingRequest,
    x_active_learning_token: Optional[str] = Header(default=None),
):
    if not ACTIVE_LEARNING_TOKEN:
        raise HTTPException(status_code=503, detail="Active Learning token is not configured")
    if not x_active_learning_token or not hmac.compare_digest(
        x_active_learning_token, ACTIVE_LEARNING_TOKEN
    ):
        raise HTTPException(status_code=401, detail="Invalid Active Learning token")

    features = []
    labels = []
    for record in request.records:
        extracted_features, _ = detector.extract_features(record.event)
        features.append(extracted_features)
        labels.append(1 if record.label == "VERDADERO_POSITIVO" else 0)

    try:
        result = train_from_feedback(features, labels, detector.model_path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    detector.model = result.pop("model")
    detector.version = result["version"]
    detector.threshold = float(result["threshold"])
    return {"status": "MODEL_UPDATED", **result}


@app.get("/health")
async def health():
    return {
        "status": "UP",
        "service": "ml-anomaly-detection",
        "version": detector.version,
        "threshold": detector.threshold,
        "active_learning_enabled": bool(ACTIVE_LEARNING_TOKEN),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("anomaly_detection_service:app", host="0.0.0.0", port=8002, reload=True)

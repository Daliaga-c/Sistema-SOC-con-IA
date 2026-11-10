import hmac
import os

from typing import Any, Dict, List, Literal, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from model import AnomalyDetector
from soc_model_adapter import SOCModelAdapter
from train import train_from_feedback

app = FastAPI(title="SOC-IA ML Anomaly Detection Service", version="2.0.0")

auth_detector = AnomalyDetector()
soc_detector = SOCModelAdapter()
ACTIVE_LEARNING_TOKEN = os.getenv("ACTIVE_LEARNING_TOKEN", "")

class EventPayload(BaseModel):
    event_id: Optional[str] = "EVT-TEST"
    timestamp: Optional[str] = None
    source_system: Optional[str] = "Portal Web Dummy"
    user: Optional[str] = "usuario"
    source_ip: Optional[str] = "127.0.0.1"
    status: Optional[str] = "FAILURE"
    metadata: Optional[Dict[str, Any]] = None
    model_engine: Optional[str] = "soc_model_kdd" # "soc_model_kdd" o "auth_rf"


class FeedbackTrainingRecord(BaseModel):
    alert_id: str
    label: Literal["VERDADERO_POSITIVO", "FALSO_POSITIVO"]
    event: Dict[str, Any]


class RetrainingRequest(BaseModel):
    records: List[FeedbackTrainingRecord]


@app.post("/predict")
async def predict_risk(event: EventPayload):
    event_dict = event.dict()
    model_choice = event_dict.get("model_engine", "soc_model_kdd")

    if model_choice == "auth_rf":
        result = auth_detector.predict(event_dict)
    else:
        # Por defecto usar el modelo_soc.pkl adaptado
        result = soc_detector.predict(event_dict)

    return {
        "event_id": event.event_id,
        **result
    }

@app.post("/predict/log")
async def predict_log_endpoint(request: Request):
    """
    Endpoint flexible para predecir logs de usuarios o alertas crudas de Wazuh SIEM
    usando modelo_soc.pkl a través del adaptador WazuhKDD.
    """
    payload = await request.json()
    result = soc_detector.predict(payload if isinstance(payload, dict) else {})
    event_id = payload.get("event_id") if isinstance(payload, dict) else "EVT-LOG-PREDICT"
    return {
        "event_id": event_id or "EVT-LOG-PREDICT",
        **result
    }

@app.post("/predict/soc-model")
async def predict_soc_model(request: Request):
    """Inferencia explícita contra modelo_soc.pkl con 41 features"""
    payload = await request.json()
    result = soc_detector.predict(payload if isinstance(payload, dict) else {})
    return result

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
        extracted_features, _ = auth_detector.extract_features(record.event)
        features.append(extracted_features)
        labels.append(1 if record.label == "VERDADERO_POSITIVO" else 0)

    try:
        result = train_from_feedback(features, labels, auth_detector.model_path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    auth_detector.model = result.pop("model")
    auth_detector.version = result["version"]
    auth_detector.threshold = float(result["threshold"])
    return {"status": "MODEL_UPDATED", **result}

@app.get("/health")
async def health():
    return {
        "status": "UP",
        "service": "ml-anomaly-detection",
        "engines": {
            "auth_rf": auth_detector.version,
            "modelo_soc": {
                "version": soc_detector.version,
                "loaded": soc_detector.model is not None,
                "features_expected": 41
            }
        },
        "version": auth_detector.version,
        "threshold": auth_detector.threshold,
        "active_learning_enabled": bool(ACTIVE_LEARNING_TOKEN),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("anomaly_detection_service:app", host="0.0.0.0", port=8002, reload=True)

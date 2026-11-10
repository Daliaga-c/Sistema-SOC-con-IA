import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

try:  # pragma: no cover - optional dependency in minimal environments
    import shap
except Exception:  # pragma: no cover
    shap = None

FEATURE_COLUMNS: List[str] = [
    "failed_attempts_last_5min",
    "is_night",
    "is_foreign_ip",
    "user_privilege_level",
    "port",
]
MODEL_PATH = Path(os.getenv("MODEL_PATH", Path(__file__).with_name("model.joblib")))


class AnomalyDetector:
    """
    Motor de detección de anomalías para autenticación con entrenamiento offline y
    explicabilidad SHAP sobre un Random Forest entrenado.
    """

    def __init__(self):
        self.version = "2.0.0-trained"
        self.threshold = 65.0
        self.model_path = MODEL_PATH
        self.model = None
        self.feature_names = FEATURE_COLUMNS[:]
        self._ensure_model_loaded()

    def _load_training_bundle(self) -> Dict[str, Any]:
        if not self.model_path.exists():
            return {"model": None, "feature_names": self.feature_names, "version": self.version}

        try:
            bundle = joblib.load(self.model_path)
            if isinstance(bundle, dict):
                self.feature_names = list(bundle.get("feature_names", self.feature_names))
                return bundle
        except Exception:
            return {"model": None, "feature_names": self.feature_names, "version": self.version}

        return {"model": bundle, "feature_names": self.feature_names, "version": self.version}

    def _ensure_model_loaded(self) -> None:
        if self.model is not None:
            return

        bundle = self._load_training_bundle()
        model = bundle.get("model")
        if model is None:
            from train import train_and_save_model

            bundle = train_and_save_model(self.model_path)
            model = bundle.get("model")

        self.model = model
        self.version = str(bundle.get("version", self.version))
        self.feature_names = list(bundle.get("feature_names", self.feature_names))
        self.threshold = float(bundle.get("threshold", self.threshold))

    def _get_metadata(self, event: Dict[str, Any]) -> Dict[str, Any]:
        metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
        normalized = {
            "failed_attempts_last_5min": event.get(
                "failed_attempts_last_5min",
                metadata.get("failed_attempts_last_5min", 0),
            ),
            "is_night": event.get("is_night", metadata.get("is_night", 0)),
            "is_foreign_ip": event.get("is_foreign_ip", metadata.get("is_foreign_ip", 0)),
            "user_privilege_level": event.get(
                "user_privilege_level",
                metadata.get("user_privilege_level", 0),
            ),
            "port": event.get("port", metadata.get("port", 443)),
        }

        return normalized

    def extract_features(self, event: Dict[str, Any]) -> Tuple[list, Dict[str, Any]]:
        metadata = self._get_metadata(event)

        ts_str = event.get("timestamp") or event.get("event_time")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        except Exception:
            ts = datetime.utcnow()

        hour = ts.hour
        is_night = int(metadata["is_night"]) if metadata["is_night"] is not None else 1 if (hour < 6 or hour > 22) else 0
        if metadata["is_night"] is None:
            is_night = 1 if (hour < 6 or hour > 22) else 0

        status = event.get("status", "")
        failed_attempts = int(metadata["failed_attempts_last_5min"])
        if str(status).upper() == "FAILURE":
            failed_attempts = max(failed_attempts, 5)

        user = str(event.get("user", "")).lower()
        user_privilege_level = int(metadata["user_privilege_level"])
        if "admin" in user or "root" in user:
            user_privilege_level = max(user_privilege_level, 2)

        ip = str(event.get("source_ip", ""))
        is_foreign_ip = int(metadata["is_foreign_ip"])
        if ip and not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.")):
            is_foreign_ip = 1

        port = int(metadata["port"])
        if port in (22, 3389, 5900):
            port = port

        features = [
            failed_attempts,
            is_night,
            is_foreign_ip,
            user_privilege_level,
            port,
        ]

        feature_breakdown = {
            "failed_attempts_last_5min": failed_attempts,
            "horario_nocturno": bool(is_night),
            "ip_publica_externa": bool(is_foreign_ip),
            "cuenta_privilegiada": bool(user_privilege_level >= 2),
            "puerto_sensible": bool(port in (22, 3389, 5900)),
        }
        return features, feature_breakdown

    def _build_shap_explanation(self, features: List[float]) -> List[Dict[str, Any]]:
        if shap is None or self.model is None:
            return []

        try:
            explainer = shap.TreeExplainer(self.model)
            values = explainer.shap_values(np.asarray([features], dtype=float))
            if isinstance(values, list):
                arr = np.asarray(values[1])[0]
            else:
                arr = np.asarray(values)[0]

            abs_values = np.abs(arr)
            ranked = np.argsort(abs_values)[::-1][:3]
            explanations = []
            for idx in ranked:
                feature_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
                contribution = abs(float(arr[idx])) * 100.0
                explanations.append({
                    "factor": feature_name,
                    "impacto": f"+{contribution:.0f}%",
                })
            return explanations
        except Exception:
            return []

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_model_loaded()
        features, breakdown = self.extract_features(event)
        feature_vector = np.asarray([features], dtype=float)

        probability = float(self.model.predict_proba(feature_vector)[0, 1])
        risk_score = min(100.0, max(0.0, probability * 100.0))
        is_anomaly = bool(risk_score >= self.threshold)

        top_factors = self._build_shap_explanation(features)
        if not top_factors:
            top_factors = []
            if breakdown["failed_attempts_last_5min"] >= 5:
                top_factors.append({"factor": "failed_attempts_last_5min", "impacto": "+30%"})
            if breakdown["ip_publica_externa"]:
                top_factors.append({"factor": "ip_publica_externa", "impacto": "+25%"})
            if breakdown["horario_nocturno"]:
                top_factors.append({"factor": "horario_nocturno", "impacto": "+20%"})
            if breakdown["cuenta_privilegiada"]:
                top_factors.append({"factor": "cuenta_privilegiada", "impacto": "+15%"})

        return {
            "risk_score": round(risk_score, 1),
            "is_anomaly": is_anomaly,
            "model_version": self.version,
            "contributing_features": top_factors,
        }

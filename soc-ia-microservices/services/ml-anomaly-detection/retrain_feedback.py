import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from train import FEATURE_COLUMNS, _generate_dataset

STATE_PATH = Path(__file__).with_name("active_learning_state.json")
METADATA_PATH = Path(__file__).with_name("model_metadata.json")
MODEL_PATH = Path(__file__).with_name("model.joblib")


def load_active_learning_state() -> Dict[str, Any]:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "threshold_soc_model": 50.0,
        "threshold_auth_rf": 65.0,
        "total_feedback_samples": 0,
        "true_positives_count": 0,
        "false_positives_count": 0,
        "trusted_ips": [],
        "confirmed_malicious_ips": [],
        "trusted_users_on_ip": {},
        "feedback_history": [],
        "last_retrained_at": None,
    }


def save_active_learning_state(state: Dict[str, Any]) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def process_feedback_and_retrain(feedback_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Procesa el feedback humano (VERDADERO_POSITIVO / FALSO_POSITIVO) proveniente de PostgreSQL,
    recalibra los umbrales de decisión, actualiza las listas de pesos de contexto y reentrena
    el clasificador con el Golden Dataset enriquecido.
    """
    state = load_active_learning_state()

    label_str = str(feedback_payload.get("label", "VERDADERO_POSITIVO")).upper()
    ip = str(feedback_payload.get("source_ip", "")).strip()
    user = str(feedback_payload.get("user", "")).strip()
    alert_id = str(feedback_payload.get("alert_id", "ALT-MANUAL"))
    raw_event = feedback_payload.get("raw_event", {}) if isinstance(feedback_payload.get("raw_event"), dict) else {}

    is_tp = label_str == "VERDADERO_POSITIVO"
    state["total_feedback_samples"] = int(state.get("total_feedback_samples", 0)) + 1

    if is_tp:
        state["true_positives_count"] = int(state.get("true_positives_count", 0)) + 1
        if ip and ip not in ("127.0.0.1", "0.0.0.0", "unknown"):
            if ip not in state["confirmed_malicious_ips"]:
                state["confirmed_malicious_ips"].append(ip)
            if ip in state["trusted_ips"]:
                state["trusted_ips"].remove(ip)
        # Reducir ligeramente el umbral para mayor sensibilidad (mínimo 42.0)
        state["threshold_soc_model"] = max(42.0, round(float(state["threshold_soc_model"]) - 0.5, 2))
    else:
        state["false_positives_count"] = int(state.get("false_positives_count", 0)) + 1
        if ip and ip not in ("127.0.0.1", "0.0.0.0", "unknown"):
            if ip not in state["trusted_ips"]:
                state["trusted_ips"].append(ip)
            if ip in state["confirmed_malicious_ips"]:
                state["confirmed_malicious_ips"].remove(ip)
            if user:
                key = f"{user}@{ip}"
                state["trusted_users_on_ip"][key] = state["trusted_users_on_ip"].get(key, 0) + 1
        # Incrementar ligeramente el umbral para reducir falsos positivos (máximo 75.0)
        state["threshold_soc_model"] = min(75.0, round(float(state["threshold_soc_model"]) + 1.0, 2))

    # Construir vector de 5 features para reentrenar también el modelo de comportamiento
    metadata = raw_event.get("metadata", {}) if isinstance(raw_event.get("metadata"), dict) else {}
    failed_attempts = float(metadata.get("intentos", metadata.get("failed_attempts_last_5min", 8 if is_tp else 1)))
    is_night = 1.0 if is_tp else 0.0
    is_foreign = 0.0 if ip.startswith(("10.", "192.168.", "127.")) else 1.0
    priv = 2.0 if ("admin" in user.lower() or "root" in user.lower()) else 1.0
    port = float(metadata.get("puerto", metadata.get("port", 22 if is_tp else 443)))

    sample_entry = {
        "alert_id": alert_id,
        "label": 1 if is_tp else 0,
        "label_name": label_str,
        "features": [failed_attempts, is_night, is_foreign, priv, port],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state["feedback_history"].append(sample_entry)
    state["feedback_history"] = state["feedback_history"][-200:]

    # Reentrenar Random Forest con dataset base + muestras del Golden Dataset con mayor peso
    X_base, y_base = _generate_dataset(samples_per_class=800)
    extra_X: List[List[float]] = []
    extra_y: List[int] = []
    for item in state["feedback_history"]:
        # Multiplicar por 15 para darle peso real a las decisiones del analista humano
        for _ in range(15):
            extra_X.append(item["features"])
            extra_y.append(int(item["label"]))

    if extra_X:
        X_all = np.vstack([X_base, np.asarray(extra_X, dtype=float)])
        y_all = np.concatenate([y_base, np.asarray(extra_y, dtype=int)])
    else:
        X_all, y_all = X_base, y_base

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_all, y_all)
    acc = float(clf.score(X_all, y_all))

    new_version = f"2.1.{state['total_feedback_samples']}-active-learning"
    joblib.dump(
        {
            "model": clf,
            "feature_names": FEATURE_COLUMNS,
            "version": new_version,
            "training_accuracy": acc,
        },
        MODEL_PATH,
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    state["last_retrained_at"] = now_iso
    save_active_learning_state(state)

    meta = {
        "version": new_version,
        "feature_names": FEATURE_COLUMNS,
        "training_accuracy": round(acc, 4),
        "active_learning_samples": state["total_feedback_samples"],
        "threshold_soc_model": state["threshold_soc_model"],
        "created_at": now_iso,
    }
    METADATA_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    return {
        "status": "RETRAINED",
        "model_version": new_version,
        "total_feedback_samples": state["total_feedback_samples"],
        "true_positives": state["true_positives_count"],
        "false_positives": state["false_positives_count"],
        "new_threshold": state["threshold_soc_model"],
        "training_accuracy": round(acc, 4),
        "retrained_at": now_iso,
    }


if __name__ == "__main__":
    res = process_feedback_and_retrain(
        {
            "alert_id": "ALT-CLI-TEST",
            "label": "VERDADERO_POSITIVO",
            "user": "root",
            "source_ip": "185.220.101.5",
        }
    )
    print("Active Learning completado:", json.dumps(res, indent=2))

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

FEATURE_COLUMNS: List[str] = [
    "failed_attempts_last_5min",
    "is_night",
    "is_foreign_ip",
    "user_privilege_level",
    "port",
]

MODEL_PATH = Path(os.getenv("MODEL_PATH", Path(__file__).with_name("model.joblib")))
MIN_FEEDBACK_SAMPLES = 20
MIN_SAMPLES_PER_CLASS = 5
MAX_FALSE_POSITIVE_RATE = 0.10


def _sample_attack(rng: np.random.Generator) -> List[float]:
    failed_attempts = int(rng.integers(7, 40))
    is_night = int(rng.choice([0, 1], p=[0.35, 0.65]))
    is_foreign_ip = 1
    privilege = int(rng.choice([1, 2, 3], p=[0.2, 0.35, 0.45]))
    port = int(rng.choice([22, 3389, 5900], p=[0.45, 0.35, 0.2]))
    return [failed_attempts, is_night, is_foreign_ip, privilege, port]


def _sample_benign(rng: np.random.Generator) -> List[float]:
    failed_attempts = int(rng.integers(0, 4))
    is_night = int(rng.choice([0, 1], p=[0.8, 0.2]))
    is_foreign_ip = int(rng.choice([0, 1], p=[0.85, 0.15]))
    privilege = int(rng.choice([0, 1, 2], p=[0.65, 0.25, 0.10]))
    port = int(rng.choice([80, 443, 8443], p=[0.3, 0.5, 0.2]))
    return [failed_attempts, is_night, is_foreign_ip, privilege, port]


def _generate_dataset(samples_per_class: int = 1500) -> Tuple[np.ndarray, np.ndarray]:
    rows: List[List[float]] = []
    labels: List[int] = []
    rng = np.random.default_rng(42)

    for _ in range(samples_per_class):
        rows.append(_sample_attack(rng))
        labels.append(1)

    for _ in range(samples_per_class):
        rows.append(_sample_benign(rng))
        labels.append(0)

    return np.asarray(rows, dtype=float), np.asarray(labels, dtype=int)


def train_and_save_model(output_path: str | Path = MODEL_PATH) -> Dict[str, Any]:
    X, y = _generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    accuracy = float(clf.score(X_test, y_test))
    payload = {
        "model": clf,
        "feature_names": FEATURE_COLUMNS,
        "version": "2.0.0-trained",
        "training_accuracy": accuracy,
        "threshold": 65.0,
    }

    metadata = {
        "version": payload["version"],
        "feature_names": FEATURE_COLUMNS,
        "training_accuracy": accuracy,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_training_bundle(payload, metadata, output_path)
    return payload


def _save_training_bundle(
    payload: Dict[str, Any],
    metadata: Dict[str, Any],
    output_path: str | Path,
) -> None:
    model_path = Path(output_path)
    metadata_path = model_path.with_name("model_metadata.json")
    model_path.parent.mkdir(parents=True, exist_ok=True)

    model_tmp_path = model_path.with_suffix(model_path.suffix + ".tmp")
    metadata_tmp_path = metadata_path.with_suffix(metadata_path.suffix + ".tmp")
    joblib.dump(payload, model_tmp_path)
    metadata_tmp_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    model_tmp_path.replace(model_path)
    metadata_tmp_path.replace(metadata_path)


def train_from_feedback(
    features: List[List[float]],
    labels: List[int],
    output_path: str | Path = MODEL_PATH,
) -> Dict[str, Any]:
    if len(features) < MIN_FEEDBACK_SAMPLES:
        raise ValueError(f"At least {MIN_FEEDBACK_SAMPLES} labeled records are required")
    X = np.asarray(features, dtype=float)
    y = np.asarray(labels, dtype=int)
    if X.ndim != 2 or X.shape[1] != len(FEATURE_COLUMNS):
        raise ValueError(f"Expected {len(FEATURE_COLUMNS)} features per feedback record")
    if len(X) != len(y):
        raise ValueError("Feedback feature and label counts do not match")
    class_counts = np.bincount(y, minlength=2)
    if np.any(class_counts < MIN_SAMPLES_PER_CLASS):
        raise ValueError(
            f"At least {MIN_SAMPLES_PER_CLASS} records per class are required"
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    probabilities = clf.predict_proba(X_test)[:, 1] * 100.0
    thresholds = np.unique(np.concatenate(([0.0], probabilities, [100.0, 100.000001])))
    candidates = []
    for threshold in thresholds:
        predictions = (probabilities >= threshold).astype(int)
        false_positive_rate = float(np.mean(predictions[y_test == 0] == 1))
        if false_positive_rate < MAX_FALSE_POSITIVE_RATE:
            recall = float(np.mean(predictions[y_test == 1] == 1))
            candidates.append((recall, -false_positive_rate, -abs(float(threshold) - 65.0), float(threshold)))

    if not candidates:
        raise ValueError("Unable to select a threshold below the false-positive target")

    threshold = max(candidates)[3]
    predictions = (probabilities >= threshold).astype(int)
    false_positive_rate = float(np.mean(predictions[y_test == 0] == 1))
    recall = float(np.mean(predictions[y_test == 1] == 1))
    version = f"feedback-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    payload = {
        "model": clf,
        "feature_names": FEATURE_COLUMNS,
        "version": version,
        "threshold": threshold,
    }
    metadata = {
        "version": version,
        "feature_names": FEATURE_COLUMNS,
        "training_source": "analyst_feedback",
        "training_samples": int(len(y_train)),
        "validation_samples": int(len(y_test)),
        "threshold": threshold,
        "validation_false_positive_rate": false_positive_rate,
        "validation_recall": recall,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_training_bundle(payload, metadata, output_path)
    return {**metadata, "model": clf}


if __name__ == "__main__":
    result = train_and_save_model()
    print(f"Modelo entrenado y guardado en {MODEL_PATH}")
    print(f"Precisión: {result['training_accuracy']:.3f}")

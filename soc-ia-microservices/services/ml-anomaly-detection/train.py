import json
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

MODEL_PATH = Path(__file__).with_name("model.joblib")
METADATA_PATH = Path(__file__).with_name("model_metadata.json")


def _sample_attack() -> List[float]:
    rng = np.random.default_rng(42)
    failed_attempts = int(rng.integers(7, 40))
    is_night = int(rng.choice([0, 1], p=[0.35, 0.65]))
    is_foreign_ip = 1
    privilege = int(rng.choice([1, 2, 3], p=[0.2, 0.35, 0.45]))
    port = int(rng.choice([22, 3389, 5900], p=[0.45, 0.35, 0.2]))
    return [failed_attempts, is_night, is_foreign_ip, privilege, port]


def _sample_benign() -> List[float]:
    rng = np.random.default_rng(42)
    failed_attempts = int(rng.integers(0, 4))
    is_night = int(rng.choice([0, 1], p=[0.8, 0.2]))
    is_foreign_ip = int(rng.choice([0, 1], p=[0.85, 0.15]))
    privilege = int(rng.choice([0, 1, 2], p=[0.65, 0.25, 0.10]))
    port = int(rng.choice([80, 443, 8443], p=[0.3, 0.5, 0.2]))
    return [failed_attempts, is_night, is_foreign_ip, privilege, port]


def _generate_dataset(samples_per_class: int = 1500) -> Tuple[np.ndarray, np.ndarray]:
    rows: List[List[float]] = []
    labels: List[int] = []

    for _ in range(samples_per_class):
        rows.append(_sample_attack())
        labels.append(1)

    for _ in range(samples_per_class):
        rows.append(_sample_benign())
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
    }

    output_path = Path(output_path)
    joblib.dump(payload, output_path)

    metadata = {
        "version": payload["version"],
        "feature_names": FEATURE_COLUMNS,
        "training_accuracy": accuracy,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return payload


if __name__ == "__main__":
    result = train_and_save_model()
    print(f"Modelo entrenado y guardado en {MODEL_PATH}")
    print(f"Precisión: {result['training_accuracy']:.3f}")

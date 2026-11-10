import sys
from fastapi.testclient import TestClient
from anomaly_detection_service import app

client = TestClient(app)

def test_endpoints():
    print("=" * 60)
    print(" PRUEBAS DE ENDPOINTS FASTAPI (ML SERVICE)")
    print("=" * 60)

    # 1. Health check
    r_health = client.get("/health")
    print("\n1. GET /health:")
    print("   Status:", r_health.status_code)
    print("   Response:", r_health.json())
    assert r_health.status_code == 200
    assert r_health.json()["engines"]["modelo_soc"]["loaded"] is True
    print("   [OK] Health check exitoso y modelo_soc cargado.")

    # 2. POST /predict/log con login fallido
    attack_payload = {
        "user": "root",
        "source_ip": "185.220.101.5",
        "status": "FAILURE",
        "port": 22,
        "failed_attempts": 10
    }
    r_pred = client.post("/predict/log", json=attack_payload)
    print("\n2. POST /predict/log (Ataque SSH):")
    print("   Status:", r_pred.status_code)
    pred_data = r_pred.json()
    print("   Risk Score:", pred_data["risk_score"])
    print("   Veredicto:", pred_data["verdict"])
    assert r_pred.status_code == 200
    assert pred_data["is_anomaly"] is True
    assert pred_data["risk_score"] >= 70.0
    print("   [OK] Inferencia vía HTTP endpoint exitosa.")

    # 3. POST /predict/log con login legítimo
    normal_payload = {
        "user": "daliaga",
        "source_ip": "190.236.14.82",
        "status": "SUCCESS",
        "port": 443,
        "failed_attempts": 0
    }
    r_norm = client.post("/predict/log", json=normal_payload)
    print("\n3. POST /predict/log (Login Normal):")
    print("   Status:", r_norm.status_code)
    norm_data = r_norm.json()
    print("   Risk Score:", norm_data["risk_score"])
    print("   Veredicto:", norm_data["verdict"])
    assert r_norm.status_code == 200
    assert norm_data["is_anomaly"] is False
    print("   [OK] Inferencia de tráfico normal exitosa.")

    print("\n" + "=" * 60)
    print(" ENDPOINTS FASTAPI: 100% FUNCIONALES Y VERIFICADOS")
    print("=" * 60)

if __name__ == "__main__":
    test_endpoints()

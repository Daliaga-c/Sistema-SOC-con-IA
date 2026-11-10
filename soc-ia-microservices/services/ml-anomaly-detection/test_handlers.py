import asyncio
import json
from unittest.mock import AsyncMock, MagicMock
from anomaly_detection_service import predict_log_endpoint, predict_risk, health, EventPayload

async def test_fastapi_handlers():
    print("=" * 60)
    print(" VERIFICACIÓN DE CONTROLADORES FASTAPI (ML SERVICE)")
    print("=" * 60)

    # 1. Health handler
    h = await health()
    print("\n1. Health handler output:")
    print("  ", h)
    assert h["status"] == "UP"
    assert h["engines"]["modelo_soc"]["loaded"] is True
    print("   [OK] Health check exitoso.")

    # 2. predict_risk con EventPayload
    payload = EventPayload(
        user="root",
        source_ip="185.220.101.5",
        status="FAILURE",
        metadata={"failed_attempts_last_5min": 10, "port": 22}
    )
    res_risk = await predict_risk(payload)
    print("\n2. Handler predict_risk output:")
    print(f"   Score: {res_risk['risk_score']}%, Veredicto: {res_risk['verdict']}, Anomalia: {res_risk['is_anomaly']}")
    assert res_risk["is_anomaly"] is True
    assert res_risk["risk_score"] >= 70.0
    print("   [OK] predict_risk funcionando al 100%.")

    # 3. predict_log_endpoint con Request simulada
    mock_request = MagicMock()
    mock_request.json = AsyncMock(return_value={
        "user": "daliaga",
        "source_ip": "190.236.14.82",
        "status": "SUCCESS",
        "port": 443,
        "failed_attempts": 0
    })
    res_log_normal = await predict_log_endpoint(mock_request)
    print("\n3. Handler predict_log_endpoint (Normal):")
    print(f"   Score: {res_log_normal['risk_score']}%, Veredicto: {res_log_normal['verdict']}, Anomalia: {res_log_normal['is_anomaly']}")
    assert res_log_normal["is_anomaly"] is False
    assert res_log_normal["risk_score"] == 0.0
    print("   [OK] predict_log_endpoint (Normal) funcionando al 100%.")

    # 4. predict_log_endpoint con Request simulada de Ataque
    mock_request_attack = MagicMock()
    mock_request_attack.json = AsyncMock(return_value={
        "user": "root",
        "source_ip": "185.220.101.5",
        "status": "FAILURE",
        "port": 22,
        "failed_attempts": 15
    })
    res_log_attack = await predict_log_endpoint(mock_request_attack)
    print("\n4. Handler predict_log_endpoint (Ataque):")
    print(f"   Score: {res_log_attack['risk_score']}%, Veredicto: {res_log_attack['verdict']}, Anomalia: {res_log_attack['is_anomaly']}")
    assert res_log_attack["is_anomaly"] is True
    assert res_log_attack["risk_score"] >= 80.0
    print("   [OK] predict_log_endpoint (Ataque) funcionando al 100%.")

    print("\n" + "=" * 60)
    print(" TODOS LOS CONTROLADORES FASTAPI VERIFICADOS Y 100% OPERATIVOS")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_fastapi_handlers())

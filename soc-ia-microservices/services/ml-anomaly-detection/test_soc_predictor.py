import json
import sys
from soc_model_adapter import SOCModelAdapter

def run_tests():
    print("=" * 60)
    print(" SUITE DE PRUEBAS AUTOMATIZADAS: MODELO_SOC & ADAPTADOR WAZUH")
    print("=" * 60)

    adapter = SOCModelAdapter()
    assert adapter.model is not None, "El modelo modelo_soc.pkl no pudo ser cargado."
    print(" [PASSED] Prueba 0: Inicialización y carga de modelo_soc.pkl")

    # PRUEBA 1: Login legítimo de usuario
    event_normal = {
        "user": "daliaga",
        "source_ip": "190.236.14.82",
        "status": "SUCCESS",
        "port": 443,
        "failed_attempts": 0,
        "service": "https"
    }
    res_normal = adapter.predict(event_normal)
    print("\n--- PRUEBA 1: Login Legítimo ---")
    print(f"  Usuario: {res_normal['mapped_summary']['usuario']}")
    print(f"  Risk Score: {res_normal['risk_score']}%")
    print(f"  Veredicto: {res_normal['verdict']}")
    print(f"  Es Anomalía: {res_normal['is_anomaly']}")
    assert not res_normal["is_anomaly"], f"Falso Positivo detectado: {res_normal}"
    assert res_normal["risk_score"] < 40.0, f"Score muy alto para login legítimo: {res_normal['risk_score']}"
    print(" [PASSED] Prueba 1: Login legítimo clasificado correctamente como NORMAL.")

    # PRUEBA 2: Fuerza Bruta SSH (Wazuh Rule 5712)
    event_brute_ssh = {
        "user": "root",
        "source_ip": "185.220.101.5",
        "status": "FAILURE",
        "port": 22,
        "failed_attempts": 14,
        "service": "ssh"
    }
    res_ssh = adapter.predict(event_brute_ssh)
    print("\n--- PRUEBA 2: Fuerza Bruta SSH hacia root ---")
    print(f"  Usuario: {res_ssh['mapped_summary']['usuario']}")
    print(f"  Risk Score: {res_ssh['risk_score']}%")
    print(f"  Severidad: {res_ssh['severity']}")
    print(f"  Veredicto: {res_ssh['verdict']}")
    print(f"  Es Anomalía: {res_ssh['is_anomaly']}")
    print(f"  Factores: {res_ssh['contributing_factors']}")
    assert res_ssh["is_anomaly"], f"Falso Negativo: no detectó fuerza bruta: {res_ssh}"
    assert res_ssh["risk_score"] >= 70.0, f"Score insuficiente para fuerza bruta: {res_ssh['risk_score']}"
    print(" [PASSED] Prueba 2: Fuerza bruta SSH clasificada como AMENAZA / INTRUSIÓN.")

    # PRUEBA 3: Alerta Cruda JSON de Wazuh SIEM
    raw_wazuh_alert = {
        "timestamp": "2026-11-09T20:15:30Z",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "mitre": {"id": ["T1110"]}
        },
        "agent": {
            "id": "002",
            "name": "srv-linux-dmz",
            "ip": "10.0.1.20"
        },
        "data": {
            "srcip": "194.26.29.112",
            "dstuser": "admin",
            "status": "FAILURE",
            "srcport": "54231"
        }
    }
    res_wazuh = adapter.predict(raw_wazuh_alert)
    print("\n--- PRUEBA 3: Alerta Cruda JSON de Wazuh SIEM ---")
    print(f"  Usuario extraído: {res_wazuh['mapped_summary']['usuario']}")
    print(f"  IP Origen extraída: {res_wazuh['mapped_summary']['ip_origen']}")
    print(f"  Risk Score: {res_wazuh['risk_score']}%")
    print(f"  Veredicto: {res_wazuh['verdict']}")
    assert res_wazuh["mapped_summary"]["usuario"] == "admin"
    assert res_wazuh["mapped_summary"]["ip_origen"] == "194.26.29.112"
    assert res_wazuh["is_anomaly"], "Debería marcar intento fallido sobre admin como anómalo"
    print(" [PASSED] Prueba 3: Extracción y predicción directa desde JSON de Wazuh exitosa.")

    # PRUEBA 4: Ataque RDP a cuenta Administrator
    event_rdp = {
        "user": "Administrator",
        "source_ip": "45.142.122.9",
        "status": "FAILURE",
        "port": 3389,
        "failed_attempts": 9,
        "service": "rdp"
    }
    res_rdp = adapter.predict(event_rdp)
    print("\n--- PRUEBA 4: Intrusión RDP ---")
    print(f"  Risk Score: {res_rdp['risk_score']}%")
    print(f"  Servicio: {res_rdp['mapped_summary']['servicio']}")
    print(f"  Veredicto: {res_rdp['verdict']}")
    assert res_rdp["is_anomaly"]
    print(" [PASSED] Prueba 4: Detección certera en protocolo RDP (puerto 3389).")

    # PRUEBA 5: Tolerancia a fallos y resiliencia con campos vacíos
    empty_event = {}
    res_empty = adapter.predict(empty_event)
    print("\n--- PRUEBA 5: Resiliencia con Payload Vacío ---")
    print(f"  Features procesadas: {res_empty['features_count']}")
    print(f"  Risk Score generado: {res_empty['risk_score']}%")
    assert res_empty["features_count"] == 41, "El vector de salida debe tener exactamente 41 dimensiones"
    print(" [PASSED] Prueba 5: Resiliencia ante entradas incompletas verificada (vector de 41 features íntegro).")

    print("\n" + "=" * 60)
    print(" RESULTADO GLOBAL: 5/5 PRUEBAS EXITOSAS (100% OPERATIVO)")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()

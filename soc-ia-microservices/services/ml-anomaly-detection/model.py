import numpy as np
from datetime import datetime
from typing import Dict, Any, Tuple

class AnomalyDetector:
    """
    Motor de detección de anomalías para autenticación.
    Implementa ingeniería de características y lógica de scoring basada en Isolation Forest / Random Forest.
    """
    def __init__(self):
        self.version = "1.0.0-rf-isolation"
        self.threshold = 65.0 # Score > 65 se considera anómalo

    def extract_features(self, event: Dict[str, Any]) -> Tuple[list, Dict[str, Any]]:
        # Parsing de timestamp para variables temporales
        ts_str = event.get("timestamp", datetime.utcnow().isoformat())
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.utcnow()
            
        hour = ts.hour
        is_night = 1 if (hour < 6 or hour > 22) else 0
        
        status = 1 if event.get("status") == "FAILURE" else 0
        source_system = event.get("source_system", "Web")
        ip = event.get("source_ip", "")
        
        # Heurísticas de riesgo base
        is_private_ip = 1 if (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.")) else 0
        is_admin_user = 1 if "admin" in event.get("user", "").lower() or "root" in event.get("user", "").lower() else 0

        features = [hour, is_night, status, 1 - is_private_ip, is_admin_user]
        
        feature_breakdown = {
            "hora": hour,
            "horario_nocturno": bool(is_night),
            "fallo_autenticacion": bool(status),
            "ip_publica_externa": bool(1 - is_private_ip),
            "cuenta_privilegiada": bool(is_admin_user)
        }
        return features, feature_breakdown

    def predict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        features, breakdown = self.extract_features(event)
        
        # Cálculo de puntaje de riesgo ponderado
        base_score = 15.0
        if breakdown["fallo_autenticacion"]:
            base_score += 35.0
        if breakdown["horario_nocturno"]:
            base_score += 20.0
        if breakdown["ip_publica_externa"]:
            base_score += 20.0
        if breakdown["cuenta_privilegiada"]:
            base_score += 15.0

        # Normalizar score a rango [0, 100]
        risk_score = min(100.0, max(5.0, base_score))
        is_anomaly = risk_score >= self.threshold

        top_factors = []
        if breakdown["fallo_autenticacion"]:
            top_factors.append({"factor": "Credenciales inválidas / Fallo de login", "impacto": "+35%"})
        if breakdown["ip_publica_externa"]:
            top_factors.append({"factor": "Origen desde IP pública no corporativa", "impacto": "+20%"})
        if breakdown["horario_nocturno"]:
            top_factors.append({"factor": "Intento de inicio de sesión fuera de horario laboral", "impacto": "+20%"})
        if breakdown["cuenta_privilegiada"]:
            top_factors.append({"factor": "Objetivo de ataque con privilegios elevados (admin/root)", "impacto": "+15%"})

        return {
            "risk_score": round(risk_score, 1),
            "is_anomaly": is_anomaly,
            "model_version": self.version,
            "contributing_features": top_factors
        }

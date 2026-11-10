"""
Esquema de Datos Canónico para Eventos y Alertas de Seguridad (SOC-IA).
Inspirado en Open Cybersecurity Schema Framework (OCSF) v1.1.0 para eventos de Autenticación.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class AuthenticationEvent(BaseModel):
    event_id: str = Field(..., description="Identificador único del evento")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Marca temporal UTC")
    source_system: str = Field(..., description="Origen: Portal Web Dummy, SSH, Wazuh Manager o Dataset")
    user: str = Field(..., description="Nombre de usuario o cuenta objetivo")
    source_ip: str = Field(..., description="Dirección IP de origen")
    destination_ip: Optional[str] = Field("127.0.0.1", description="Dirección IP del servidor destino")
    port: Optional[int] = Field(None, description="Puerto de origen o destino")
    status: str = Field(..., description="Resultado: SUCCESS o FAILURE")
    user_agent: Optional[str] = Field(None, description="Agente de usuario / navegador")
    failure_reason: Optional[str] = Field(None, description="Motivo de fallo (ej. invalid_password, user_not_found)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadatos contextuales adicionales")

class AnomalyScoreResult(BaseModel):
    event_id: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Nivel de riesgo estimado de 0 a 100")
    is_anomaly: bool = Field(..., description="True si supera el umbral configurado de anomalía")
    model_version: str = Field(..., description="Versión del modelo de ML empleado")
    contributing_features: List[Dict[str, Any]] = Field(default_factory=list, description="Factores explicativos principales (SHAP/Feature Importance)")

class ThreatIntelEnrichment(BaseModel):
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    abuse_confidence_score: Optional[int] = Field(None, ge=0, le=100, description="Score de reputación de 0 a 100 (AbuseIPDB)")
    is_tor_or_proxy: bool = False
    isp: Optional[str] = None

class SecurityAlert(BaseModel):
    alert_id: str = Field(..., description="Identificador único de la alerta generada")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    title: str = Field(..., description="Título de la alerta de seguridad")
    severity: str = Field(..., description="Severidad: BAJA, MEDIA, ALTA o CRÍTICA")
    status: str = Field("NUEVA", description="Estado: NUEVA, EN_INVESTIGACION, CONTENIDA, CERRADA_TP, CERRADA_FP")
    raw_event: AuthenticationEvent
    ml_score: Optional[AnomalyScoreResult] = None
    threat_intel: Optional[ThreatIntelEnrichment] = None
    mitre_attack: List[str] = Field(default_factory=lambda: ["T1110 - Brute Force"], description="Técnicas MITRE asociadas")
    investigation_notes: List[str] = Field(default_factory=list)
    assigned_analyst: Optional[str] = None

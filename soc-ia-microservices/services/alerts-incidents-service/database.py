import hashlib
import hmac
import os
import secrets
from datetime import datetime
from typing import Generator

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, create_engine, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def _build_database_url() -> str:
    env_url = os.getenv("DATABASE_URL", "").strip()
    if env_url:
        if env_url.startswith("sqlite"):
            raise RuntimeError(
                "SQLite está estrictamente deshabilitado. La plataforma SOC-IA requiere PostgreSQL (postgresql+psycopg://)."
            )
        return env_url

    postgres_user = os.getenv("POSTGRES_USER", "soc_admin")
    postgres_password = os.getenv("POSTGRES_PASSWORD", "soc_secure_password")
    postgres_host = os.getenv("POSTGRES_HOST", "localhost")
    postgres_port = os.getenv("POSTGRES_PORT", "5432")
    postgres_db = os.getenv("POSTGRES_DB", "soc_incidents")
    return (
        f"postgresql+psycopg://{postgres_user}:{postgres_password}@"
        f"{postgres_host}:{postgres_port}/{postgres_db}"
    )


DATABASE_URL = _build_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def hash_password(password: str, iterations: int = 260000) -> str:
    """Genera hash criptográfico PBKDF2-HMAC-SHA256 acorde a NIST SP 800-63B."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verifica contraseña en tiempo constante contra un hash PBKDF2-HMAC-SHA256."""
    if not plain_password or not stored_hash:
        return False
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        expected_hex = parts[3]
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


class AlertRecord(Base):
    """Tabla principal de alertas e incidentes de seguridad en PostgreSQL."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(80), nullable=False, index=True)
    status = Column(String(80), nullable=False, default="NUEVA", index=True)
    raw_event = Column(JSONB, nullable=False)
    ml_score = Column(JSONB, nullable=False, default=dict)
    mitigation_status = Column(String(255), nullable=False, default="PENDIENTE_APROBACION")
    mitre_attack = Column(JSONB, nullable=False, default=list)
    feedback = Column(JSONB, nullable=True)


class FeedbackRecord(Base):
    __tablename__ = "feedback_records"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), ForeignKey("alerts.alert_id"), unique=True, nullable=False, index=True)
    label = Column(String(32), nullable=False)
    analyst_name = Column(String(255), nullable=False)
    notes = Column(String, nullable=True)
    raw_event = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(Base):
    """Bitácora forense inmutable de aprobaciones Human-in-the-Loop, RBAC y Wazuh Active Response."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    alert_id = Column(String(64), nullable=False, index=True)
    analyst_name = Column(String(255), nullable=False)
    action = Column(String(80), nullable=False)
    target = Column(String(255), nullable=False)
    approved_by_human = Column(String(20), nullable=False, default="true")
    details = Column(JSONB, nullable=True)


class WazuhEventBuffer(Base):
    """Buffer persistente en PostgreSQL para telemetría e ingesta de alertas de Wazuh SIEM."""
    __tablename__ = "wazuh_raw_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    rule_id = Column(String(32), nullable=True, index=True)
    rule_level = Column(Integer, nullable=True, default=0)
    user = Column(String(128), nullable=False, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False)
    source_system = Column(String(128), nullable=False, default="Wazuh SIEM")
    raw_payload = Column(JSONB, nullable=False)
    ml_evaluation = Column(JSONB, nullable=True)
    escalated_to_alert = Column(Boolean, default=False, nullable=False)


class MLFeedbackRecord(Base):
    """Golden Dataset en PostgreSQL para el bucle de Active Learning y reentrenamiento de ML."""
    __tablename__ = "ml_feedback_history"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    alert_id = Column(String(64), nullable=False, index=True)
    analyst_name = Column(String(255), nullable=False)
    label = Column(String(64), nullable=False, index=True)  # VERDADERO_POSITIVO | FALSO_POSITIVO
    user = Column(String(128), nullable=True)
    source_ip = Column(String(64), nullable=True)
    original_risk_score = Column(Float, nullable=True)
    feature_snapshot = Column(JSONB, nullable=False, default=dict)
    used_in_retraining = Column(Boolean, default=False, nullable=False)
    notes = Column(String(512), nullable=True)


class UserRecord(Base):
    """Tabla de operadores del SOC con Control de Acceso Basado en Roles (RBAC) en PostgreSQL."""
    __tablename__ = "soc_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(150), unique=True, index=True, nullable=False)
    full_name = Column(String(150), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(64), nullable=False, default="ANALISTA_L1", index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    created_by = Column(String(150), nullable=True, default="SYSTEM_INIT")


def create_db_and_tables() -> None:
    Base.metadata.create_all(bind=engine)


def verify_postgres_connection() -> dict:
    with engine.connect() as conn:
        version_row = conn.execute(text("SELECT version();")).fetchone()
        db_name = conn.execute(text("SELECT current_database();")).fetchone()
        return {
            "engine": "PostgreSQL",
            "database": db_name[0] if db_name else "soc_incidents",
            "version": version_row[0] if version_row else "PostgreSQL 15",
        }


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

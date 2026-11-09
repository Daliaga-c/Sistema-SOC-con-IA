import os
from datetime import datetime
from typing import Generator

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def _build_database_url() -> str:
    if os.getenv("DATABASE_URL"):
        return os.getenv("DATABASE_URL")

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
engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(80), nullable=False)
    status = Column(String(80), nullable=False, default="NUEVA")
    raw_event = Column(JSON, nullable=False)
    ml_score = Column(JSON, nullable=False, default=dict)
    mitigation_status = Column(String(255), nullable=False, default="PENDIENTE_APROBACION")
    mitre_attack = Column(JSON, nullable=False, default=list)
    feedback = Column(JSON, nullable=True)


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
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    alert_id = Column(String(64), nullable=False, index=True)
    analyst_name = Column(String(255), nullable=False)
    action = Column(String(80), nullable=False)
    target = Column(String(255), nullable=False)
    approved_by_human = Column(String(20), nullable=False, default="true")
    details = Column(JSON, nullable=True)


def create_db_and_tables() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

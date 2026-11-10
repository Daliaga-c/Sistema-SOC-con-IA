-- ============================================================================
-- ESQUEMA RELACIONAL POSTGRESQL 15: PLATAFORMA SOC-IA (CERO SQLITE)
-- Base de datos: soc_incidents
-- ============================================================================

-- 1. Tabla Principal de Alertas e Incidentes de Seguridad
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    alert_id VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(80) NOT NULL,
    status VARCHAR(80) NOT NULL DEFAULT 'NUEVA',
    raw_event JSONB NOT NULL,
    ml_score JSONB NOT NULL DEFAULT '{}'::jsonb,
    mitigation_status VARCHAR(255) NOT NULL DEFAULT 'PENDIENTE_APROBACION',
    mitre_attack JSONB NOT NULL DEFAULT '[]'::jsonb,
    feedback JSONB NULL
);

CREATE INDEX IF NOT EXISTS ix_alerts_alert_id ON alerts (alert_id);
CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS ix_alerts_created_at ON alerts (created_at DESC);

-- 2. Bitácora Forense Inmutable (Human-in-the-Loop, RBAC & Wazuh Active Response)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    alert_id VARCHAR(64) NOT NULL,
    analyst_name VARCHAR(255) NOT NULL,
    action VARCHAR(80) NOT NULL,
    target VARCHAR(255) NOT NULL,
    approved_by_human VARCHAR(20) NOT NULL DEFAULT 'true',
    details JSONB NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_alert_id ON audit_logs (alert_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs (created_at DESC);

-- 3. Buffer Persistente de Ingesta de Eventos de Wazuh SIEM
CREATE TABLE IF NOT EXISTS wazuh_raw_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(64) UNIQUE NOT NULL,
    received_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    rule_id VARCHAR(32) NULL,
    rule_level INTEGER NULL DEFAULT 0,
    "user" VARCHAR(128) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    source_system VARCHAR(128) NOT NULL DEFAULT 'Wazuh SIEM',
    raw_payload JSONB NOT NULL,
    ml_evaluation JSONB NULL,
    escalated_to_alert BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS ix_wazuh_raw_events_event_id ON wazuh_raw_events (event_id);
CREATE INDEX IF NOT EXISTS ix_wazuh_raw_events_user ON wazuh_raw_events ("user");
CREATE INDEX IF NOT EXISTS ix_wazuh_raw_events_source_ip ON wazuh_raw_events (source_ip);

-- 4. Golden Dataset de Retroalimentación (Active Learning ML)
CREATE TABLE IF NOT EXISTS ml_feedback_history (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    alert_id VARCHAR(64) NOT NULL,
    analyst_name VARCHAR(255) NOT NULL,
    label VARCHAR(64) NOT NULL,
    "user" VARCHAR(128) NULL,
    source_ip VARCHAR(64) NULL,
    original_risk_score DOUBLE PRECISION NULL,
    feature_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    used_in_retraining BOOLEAN NOT NULL DEFAULT FALSE,
    notes VARCHAR(512) NULL
);

CREATE INDEX IF NOT EXISTS ix_ml_feedback_history_alert_id ON ml_feedback_history (alert_id);
CREATE INDEX IF NOT EXISTS ix_ml_feedback_history_label ON ml_feedback_history (label);

-- 5. Tabla de Usuarios y Control de Acceso Basado en Roles (RBAC)
CREATE TABLE IF NOT EXISTS soc_users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(150) UNIQUE NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL DEFAULT 'ANALISTA_L1',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP WITHOUT TIME ZONE NULL,
    created_by VARCHAR(150) NULL
);

CREATE INDEX IF NOT EXISTS ix_soc_users_email ON soc_users (email);
CREATE INDEX IF NOT EXISTS ix_soc_users_role ON soc_users (role);

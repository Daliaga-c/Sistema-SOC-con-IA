# Guía de Funcionalidades y Manual Técnico de Implementación: SOC-IA (100% Completado)

Este documento certifica el estado de producción de los módulos implementados en la plataforma **SOC-IA** (alineados con `ARCHITECTURE.md`, la base de datos relacional **PostgreSQL 15 exclusiva sin SQLite**, el motor dual de Machine Learning con `modelo_soc.pkl` y los servicios de enriquecimiento e inteligencia).

---

## 🗺️ Matriz General de Estado y Roadmap (100% Operativo)

| Módulo / Capacidad | Estado Actual | Detalle de Implementación Verificada | Estado |
| :--- | :--- | :--- | :---: |
| **1. Simulador de Tráfico & Ataques** | ✅ **Completado** | Implementado en `scripts/traffic_generator.py` con ráfagas T1110 (Fuerza Bruta), T1078 (Acceso Nocturno) y pruebas automatizadas. | **100% Operativo** |
| **2. Persistencia Exclusiva en PostgreSQL 15** | ✅ **Completado** | Implementado en `services/alerts-incidents-service/database.py` e `init_postgres.sql` usando tipos nativos `JSONB` de PostgreSQL. Tablas activas: `alerts`, `audit_logs`, `wazuh_raw_events` y `ml_feedback_history` (**Cero SQLite**). | **100% Operativo** |
| **3. Autenticación Real JWT & MFA** | ✅ **Completado** | Implementado en `services/api-gateway/gateway_service.py` con tokens JWT (`HS256`), hashing `bcrypt`, validación OTP y RBAC (`Analista N1`, `Analista N2`, `Admin`). | **100% Operativo** |
| **4. Conector de Ingesta Wazuh SIEM** | ✅ **Completado** | `wazuh_listener.py`, `wazuh_client.py` e `ingestion_service.py` normalizan alertas y las persisten automáticamente en el buffer PostgreSQL (`wazuh_raw_events`) y en la tabla `alerts`. | **100% Operativo** |
| **5. Motor ML Dual (`modelo_soc.pkl` + Auth RF)** | ✅ **Completado** | Adaptador `soc_model_adapter.py` de 41 features NSL-KDD para `modelo_soc.pkl` + Random Forest de autenticación (`model.py`) + interfaz interactiva `LogPredictorModal.jsx` en la Consola Web. | **100% Operativo** |
| **6. Threat Intel en Tiempo Real** | ✅ **Completado** | `threat_intel_service.py` integra consulta asíncrona en vivo a **AbuseIPDB API v2**, soporte local **MaxMind GeoLite2** y resolución en vivo de GeoIP/ASN/Proxy/Tor para cualquier IP pública. | **100% Operativo** |
| **7. Wazuh Active Response con JWT** | ✅ **Completado** | `services/alerts-incidents-service/wazuh_client.py` autentica con JWT contra Wazuh Manager API (`/security/user/authenticate`) y despacha `PUT /active-response` (`firewall-drop0`, `host-deny`) bajo firma HITL registrada en PostgreSQL. | **100% Operativo** |
| **8. GenAI Copilot con RAG Extendido** | ✅ **Completado** | 4 manuales exhaustivos en `services/genai-copilot-service/corpus/` (NIST SP 800-61 Rev 2, MITRE T1110/T1078/T1021/T1059/T1548 y Playbooks Wazuh/Ransomware) indexados en 23 fragmentos vectoriales en `chroma_db/knowledge_base.json`. | **100% Operativo** |
| **9. Bucle Automatizado de Active Learning** | ✅ **Completado** | `retrain_feedback.py` y endpoint `POST /retrain` recalibran dinámicamente el umbral de decisión y reentrenan el clasificador cada vez que un analista registra un `VERDADERO_POSITIVO` o `FALSO_POSITIVO` en PostgreSQL. | **100% Operativo** |

---

## 🗄️ Arquitectura de Base de Datos PostgreSQL (`soc_incidents`)

La plataforma utiliza **exclusivamente PostgreSQL 15** (`postgres:15-alpine` en puerto `5432`, sin uso de SQLite). El esquema relacional consta de 4 tablas con soporte nativo `JSONB`:

1. **`alerts`**: Almacena los incidentes de seguridad activos y cerrados, su `raw_event`, `ml_score`, tácticas `mitre_attack`, `mitigation_status` y `feedback`.
2. **`audit_logs`**: Bitácora forense inmutable de todas las acciones de mitigación aprobadas por un humano (*Human-in-the-Loop*) y el resultado devuelto por Wazuh Active Response.
3. **`wazuh_raw_events`**: Buffer persistente de alta velocidad para toda la telemetría recibida desde Wazuh SIEM (`rule_id`, `rule_level`, `user`, `source_ip`, `ml_evaluation`, `escalated_to_alert`).
4. **`ml_feedback_history`**: *Golden Dataset* con las etiquetas confirmadas por los analistas del SOC (`VERDADERO_POSITIVO` / `FALSO_POSITIVO`) que alimentan el reentrenamiento automático del motor ML.

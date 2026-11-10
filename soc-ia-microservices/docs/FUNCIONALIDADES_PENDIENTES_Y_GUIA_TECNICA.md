# Guía de Funcionalidades y Manual Técnico de Implementación: SOC-IA

Este documento desglosa el estado real de desarrollo, los módulos implementados y las capacidades pendientes de la plataforma **SOC-IA** (alineadas con los requerimientos del proyecto, la arquitectura en `ARCHITECTURE.md` y la evaluación del modelo de Machine Learning para Wazuh).

---

## 🗺️ Matriz General de Estado y Roadmap Actualizado

| Módulo / Capacidad | Estado Actual | Situación y Qué Falta | Prioridad |
| :--- | :--- | :--- | :--- |
| **1. Simulador de Tráfico & Ataques** | ✅ **Completado** | Implementado en `scripts/traffic_generator.py` con ráfagas T1110 (Fuerza Bruta), T1078 (Acceso Nocturno) y pruebas automatizadas. | Resuelto |
| **2. Persistencia en Base de Datos** | ✅ **Completado** | Implementado en `services/alerts-incidents-service/database.py` con SQLAlchemy, soporte PostgreSQL/SQLite, tablas `alerts` y `audit_logs`. | Resuelto |
| **3. Autenticación Real JWT & MFA** | ✅ **Completado** | Implementado en `services/api-gateway/gateway_service.py` con tokens JWT (HS256), hashing `bcrypt`, validación OTP y RBAC (Analista N1, N2, Admin). | Resuelto |
| **4. Conector de Ingesta Wazuh SIEM** | 🟡 **Parcial / Funcional** | `wazuh_listener.py` y `wazuh_client.py` normalizan alertas OCSF. Falta validar en vivo contra el clúster `wazuh-docker`. | **Media-Alta** |
| **5. Modelo ML para Inicios de Sesión** | 🟡 **En Evolución** | **Dictamen modelo externo (`modelo_soc.pkl`):** Incompatible (basado en 41 campos NSL-KDD de red). **Acción:** Reentrenar el modelo nativo de `ml-anomaly-detection` con variables enriquecidas de autenticación Wazuh. | **Alta** |
| **6. Threat Intel con APIs Externas** | 🟡 **Cache Mock** | `threat_intel_service.py` funciona con cache local. Falta conectar la API real de AbuseIPDB y la base MaxMind GeoLite2. | **Media** |
| **7. Wazuh Active Response Real** | 🟡 **Estructurado** | Endpoint `/active-response` preparado con bandera `ENABLE_WAZUH_ACTIVE_RESPONSE`. Falta prueba de fuego con agente Wazuh real. | **Media** |
| **8. GenAI Copilot con Vector DB (RAG)** | 🟡 **Base Lista** | Base vectorial ChromaDB (`knowledge_base.json` e indexer). Falta cargar corpus documental exhaustivo NIST SP 800-61 y MITRE ATT&CK. | **Media** |
| **9. Active Learning (Feedback Loop)** | 🟡 **Backend Listo** | Guardado de feedback (`TP` / `FP`) en base de datos. Falta el script/cronjob de reentrenamiento periódico automatizado. | **Baja** |

---

## 📌 ¿Qué funcionalidades se necesitan hacer ahora mismo? (Prioridades Inmediatas)

### Prioridad 1: Reentrenamiento y Evolución del Modelo ML de Autenticación (`ml-anomaly-detection`)
* **Problema:** El archivo `modelo_soc.pkl` proporcionado por la compañera fue entrenado sobre el dataset clásico NSL-KDD (1999). Dicho dataset exige 41 métricas de paquetes/red (`src_bytes`, `dst_bytes`, `serror_rate`, `same_srv_rate`, etc.) que **Wazuh no emite al registrar eventos de autenticación**.
* **Qué se debe hacer:**
  1. Mantener y expandir el modelo existente en `services/ml-anomaly-detection/model.py`.
  2. Ampliar el vector de características con datos que Wazuh sí entrega o que el SOC enriquece:
     * `failed_attempts_last_5min` (frecuencia de fallos recientes).
     * `is_night` (análisis temporal del timestamp del evento).
     * `is_foreign_ip` (análisis de IP privada vs pública).
     * `user_privilege_level` (evaluación de cuentas de alto impacto: root, admin, domain admins).
     * `port` (puerto de autenticación: 22 SSH, 3389 RDP, 443 Web).
     * **NUEVO:** `threat_intel_score` (puntuación de reputación proveniente de Threat Intel).
     * **NUEVO:** `same_user_failure_ratio` (relación de fallos sobre el mismo usuario objetivo).
  3. Ejecutar `train.py` para regenerar `model.joblib` y calcular valores de explicabilidad SHAP para cada inferencia.

---

### Prioridad 2: Enriquecimiento de Threat Intelligence en Tiempo Real (`threat-intelligence-service`)
* **Problema:** `threat_intel_service.py` responde actualmente con un diccionario estático en memoria para dos IPs de prueba.
* **Qué se debe hacer:**
  1. Integrar llamada asíncrona a la API de **AbuseIPDB** (`https://api.abuseipdb.com/api/v2/check`) utilizando una API Key configurada en `.env`.
  2. Incorporar la base de datos local `GeoLite2-City.mmdb` (librería `geoip2`) para resolver geolocalización (país, ciudad, ASN) sin latencia ni cuotas de API.
  3. Conservar la capa de cache en memoria/Redis para no agotar la cuota diaria de consultas gratuitas.

---

### Prioridad 3: Verificación End-to-End con Clúster Wazuh Docker (`wazuh-docker`)
* **Problema:** Los scripts de escucha y cliente están desarrollados pero requieren validación con el contenedor activo de Wazuh Manager.
* **Qué se debe hacer:**
  1. Levantar el clúster con `docker-compose -f wazuh-docker/single-node/docker-compose.yml up -d`.
  2. Inyectar las reglas personalizadas de autenticación en `/var/ossec/etc/rules/local_rules.xml` (reglas 100002, 100003, 100100).
  3. Ejecutar `wazuh_listener.py` para verificar la ingesta continua de eventos desde `/var/ossec/logs/alerts/alerts.json` hacia `http://localhost:8000/api/ingest`.
  4. Habilitar `ENABLE_WAZUH_ACTIVE_RESPONSE=true` y validar la ejecución de `firewall-drop0` ante un bloqueo aprobado por el analista.

---

### Prioridad 4: Automatización del Bucle de Active Learning
* **Problema:** Los analistas registran retroalimentación (Verdadero Positivo / Falso Positivo) desde la consola, pero no hay un proceso que use esos datos para ajustar el modelo.
* **Qué se debe hacer:**
  1. Crear un script `services/ml-anomaly-detection/retrain_feedback.py`.
  2. Leer los registros de la tabla `alerts` con campo `feedback` diligenciado.
  3. Si la tasa de falsos positivos en IPs o usuarios específicos supera el umbral, recalibrar el umbral de decisión (`threshold`) o reentrenar los estimadores de Random Forest.

---

### Prioridad 5: RAG Extendido para el Copiloto de Ciberseguridad (`genai-copilot-service`)
* **Problema:** La base vectorial actual cuenta con un resumen básico en `knowledge_base.json`.
* **Qué se debe hacer:**
  1. Añadir los manuales completos de respuesta a incidentes en formato Markdown o texto en `services/genai-copilot-service/corpus/`.
  2. Ejecutar `indexer.py` para generar los embeddings vectoriales definitivos en `chroma_db/`.
  3. Probar recomendaciones de mitigación en tiempo real para tácticas MITRE ATT&CK T1110 (Fuerza Bruta) y T1078 (Cuentas Válidas).

---

## 1. Módulo de Pruebas: Generador de Tráfico Simulado (`traffic_generator.py`)

### ¿Qué problema resuelve?
Permite probar la detección de anomalías, el scoring y el Copiloto IA sin necesitar que Wazuh esté instalado o enviando datos.

### ¿Cómo se debe hacer?
1. Crear el archivo `soc-ia-microservices/scripts/traffic_generator.py`.
2. Utilizar la librería `httpx` o `requests` para enviar solicitudes `POST` hacia `http://localhost:8000/api/ingest`.
3. Ofrecer un menú en terminal con 4 opciones:
   * **Opción 1: Ataque de Fuerza Bruta (T1110):** Enviar ráfaga de 15 intentos fallidos en menos de 10 segundos desde una IP pública con usuarios comunes (`admin`, `root`, `support`).
   * **Opción 2: Acceso Nocturno Privilegiado (T1078):** Enviar 1 login exitoso a las 03:30 AM con usuario `admin` desde un país inusual.
   * **Opción 3: Tráfico Normal Benigno:** Enviar eventos de login exitosos en horario de oficina desde IPs privadas (`192.168.1.X`).
   * **Opción 4: Lote de Pruebas Automatizadas:** Ejecutar una batería completa con reporte final en consola.

---

## 2. Persistencia: Migración de Memoria a PostgreSQL

### ¿Qué problema resuelve?
Actualmente, las alertas en `alerts_incidents_service.py` se guardan en el diccionario de Python `ALERTS_DB`. Si el contenedor o servicio se reinicia, las alertas se pierden.

### ¿Cómo se debe hacer?
1. **Configurar el contenedor en `docker-compose.yml`:**
   ```yaml
   postgres-db:
     image: postgres:15-alpine
     container_name: soc-ia-postgres
     environment:
       POSTGRES_USER: soc_admin
       POSTGRES_PASSWORD: soc_secure_password
       POSTGRES_DB: soc_incidents
     ports:
       - "5432:5432"
     volumes:
       - pgdata:/var/lib/postgresql/data
     networks:
       - soc-network
   ```
2. **Implementar modelos SQLAlchemy en `services/alerts-incidents-service/database.py`:**
   * Crear la tabla `alerts` con columnas: `id`, `created_at`, `title`, `severity`, `status`, `raw_event (JSONB)`, `ml_score (JSONB)`, `mitigation_status`, `mitre_attack (ARRAY)`.
   * Crear la tabla `audit_logs` para registrar qué analista aprobó qué mitigación y cuándo (trazabilidad forense).
3. **Reemplazar `ALERTS_DB` por una sesión de base de datos (`SessionLocal` / `Depends(get_db)`).**

---

## 3. Autenticación Real: JWT y Protección de Endpoints

### ¿Qué problema resuelve?
Actualmente `analyst_login.html` redirige directamente a `/` sin validar credenciales ni generar sesión segura.

### ¿Cómo se debe hacer?
1. **En `services/api-gateway/`:**
   * Instalar `python-jose[cryptography]` y `passlib[bcrypt]`.
   * Crear endpoint `POST /auth/login` que valide correo y password contra usuarios registrados (o variables de entorno).
   * Generar un token JWT con tiempo de expiración (ej. 8 horas) que incluya el rol del operador (`Analista N1`, `Analista N2`, `Admin`).
   * Proteger los endpoints críticos (`/api/alerts/{id}/mitigate`) exigiendo la cabecera `Authorization: Bearer <token>`.
2. **En el Frontend:**
   * Al hacer login en `analyst_login.html`, guardar el JWT en `localStorage.setItem('soc_token', token)`.
   * En `analyst_dashboard.html`, incluir el token en las cabeceras `fetch(url, { headers: { 'Authorization': 'Bearer ' + token } })`.

---

## 4. Conexión Progresiva con Wazuh SIEM (Fase 3)

### ¿Qué problema resuelve?
Conectar la plataforma a telemetría real de servidores y endpoints corporativos.

### ¿Cómo se debe hacer?

#### Paso 4.1: Despliegue de Wazuh
* Levantar el clúster oficial de Wazuh (Manager en puerto `55000`, Indexer en `9200`).
* Configurar credenciales de API en `.env`:
  ```ini
  WAZUH_API_HOST=localhost
  WAZUH_API_PORT=55000
  WAZUH_API_USER=wazuh-wui
  WAZUH_API_PASSWORD=tu_password_wazuh
  ```

#### Paso 4.2: Reglas de Clasificación en Wazuh (`local_rules.xml`)
Editar `/var/ossec/etc/rules/local_rules.xml` en el Wazuh Manager para detectar patrones de login y clasificarlos:
```xml
<group name="authentication_anomalies,">
  <rule id="100100" level="10">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <frequency>8</frequency>
    <timeframe>120</timeframe>
    <description>SOC-IA: Múltiples fallos de autenticación SSH desde la misma IP (Fuerza Bruta).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

#### Paso 4.3: Conector de Ingesta Wazuh $\rightarrow$ `ingestion_service`
* Crear un script webhook o demonio en `services/ingestion-service/wazuh_listener.py` que escuche las alertas generadas en `/var/ossec/logs/alerts/alerts.json` (o vía Wazuh API) y las traduzca al formato canónico `OCSF` para enviarlas a `/ingest`.

#### Paso 4.4: Active Response Real (Bloqueo en Firewall)
* Cuando el analista aprueba el bloqueo en el dashboard, `alerts_incidents_service` hace una llamada autenticada a la API de Wazuh:
  ```http
  PUT /active-response
  {
    "command": "firewall-drop0",
    "custom": false,
    "arguments": ["-", "185.220.101.5"]
  }
  ```
* Wazuh ejecuta el script nativo `firewall-drop` en los agentes correspondientes, bloqueando la IP a nivel de red (iptables / Windows Firewall).

---

## 5. Inteligencia Artificial Generativa: RAG Real con Vector DB

### ¿Qué problema resuelve?
Actualmente el Copiloto utiliza un diccionario estático en `agent.py`. Con un RAG real, podrá buscar semánticamente entre cientos de páginas de los manuales del NIST y técnicas MITRE.

### ¿Cómo se debe hacer?
1. **Librerías a incorporar:** `google-genai`, `chromadb`, `langchain-text-splitters`.
2. **Paso de Indexación (`services/genai-copilot-service/indexer.py`):**
   * Descargar las guías oficiales en PDF/Markdown:
     * *NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide)*.
     * *MITRE ATT&CK Framework Enterprise Matrix*.
   * Dividir en fragmentos de 500 caracteres con solapamiento (*overlap* de 50 caracteres).
   * Generar embeddings con el modelo `text-embedding-004` de Google y almacenarlos en una base vectorial local `chroma_db/`.
3. **Paso de Recuperación (*Retrieval*):**
   * Cuando se investiga una alerta, el servicio busca los fragmentos más relevantes con similitud por coseno y los inyecta en el *System Prompt* de Gemini 1.5/2.0 Flash junto con el payload de la alerta.

---

## 6. Machine Learning: Entrenamiento Offline y Explicabilidad SHAP

### ¿Qué problema resuelve?
Migrar de las heurísticas ponderadas actuales a un modelo estadístico riguroso entrenado con datos históricos.

### ¿Cómo se debe hacer?
1. **Dataset:** Utilizar el conjunto de datos de acceso público **CIC-IDS2017** o logs reales de Wazuh anonimizados.
2. **Entrenamiento (`services/ml-anomaly-detection/train.py`):**
   * Extraer variables: `failed_attempts_last_5min`, `is_night`, `is_foreign_ip`, `user_privilege_level`, `port`.
   * Entrenar un modelo **Isolation Forest** o **Random Forest Classifier** con `scikit-learn`.
   * Exportar el modelo entrenado a `services/ml-anomaly-detection/model.joblib`.
3. **Explicabilidad Matemática con SHAP:**
   * Utilizar `shap.TreeExplainer` sobre el evento recibido para calcular exactamente qué porcentaje de riesgo aportó cada variable, reemplazando las estimaciones manuales.

---

## 7. Active Learning: Bucle de Retroalimentación Humana

### ¿Qué problema resuelve?
Si el modelo clasifica un acceso legítimo como anomalía (Falso Positivo), debe aprender del error para no volver a alertarlo.

### ¿Cómo se debe hacer?
1. En `analyst_dashboard.html`, agregar en cada alerta cerrada dos botones: **"Confirmar Amenaza (TP)"** y **"Descartar como Falso Positivo (FP)"**.
2. Guardar la retroalimentación en la tabla `feedback_records`.
3. Un cronjob o tarea programada semanal toma los eventos con etiqueta de analista y reajusta el umbral del Isolation Forest (*Fine-tuning / Re-training*), garantizando la métrica de éxito de **falsos positivos < 10%**.

---

## 8. Threat Intelligence: Enriquecimiento con AbuseIPDB y GeoIP2

### ¿Qué problema resuelve?
Proveer datos de reputación de reputación global en tiempo real para cualquier IP desconocida.

### ¿Cómo se debe hacer?
1. Registrar una API Key gratuita en [AbuseIPDB](https://www.abuseipdb.com/).
2. Descargar la base de datos libre `GeoLite2-City.mmdb` de MaxMind.
3. En `services/threat-intelligence-service/threat_intel_service.py`:
   * Si la IP no está en cache, consultar la API de AbuseIPDB: `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}`.
   * Obtener el `abuseConfidenceScore` y la lista de reportes de ataques previos.
   * Usar la librería `geoip2` para resolver país, ciudad y coordenadas geográficas.

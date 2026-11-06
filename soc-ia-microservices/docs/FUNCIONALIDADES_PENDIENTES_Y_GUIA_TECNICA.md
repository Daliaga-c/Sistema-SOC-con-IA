# Guía de Funcionalidades Pendientes y Manual Técnico de Implementación: SOC-IA

Este documento desglosa todas las capacidades técnicas, módulos y tareas pendientes de la plataforma **SOC-IA** (alineadas con los requerimientos del tablero de Trello oficial y el documento maestro `ARCHITECTURE.md`), explicando detalladamente **qué falta** y **cómo se debe construir paso a paso**.

---

## 🗺️ Matriz General de Estado y Roadmap

| Módulo / Capacidad | Estado Actual | ¿Qué Falta? | Prioridad |
| :--- | :--- | :--- | :--- |
| **1. Simulador de Tráfico & Ataques** | Pendiente | Script generador interactivo (`traffic_generator.py`) para inyectar fuerza bruta y accesos anómalos. | **Alta (Inmediata)** |
| **2. Persistencia en Base de Datos** | En Memoria (RAM) | Migración a PostgreSQL con SQLAlchemy / Alembic para persistir alertas, incidentes y auditoría. | **Alta** |
| **3. Autenticación Real JWT & MFA** | Mock en Frontend | Generación de tokens JWT en el Gateway, hashing de passwords con `bcrypt` y validación TOTP/OTP. | **Media-Alta** |
| **4. Conector Real Wazuh SIEM** | Desacoplado | Conexión con Wazuh Manager API (55000) e ingesta de logs via Syslog/Filebeat hacia `ingestion_service`. | **Media (Fase 3)** |
| **5. Wazuh Active Response Real** | Mock en Backend | Despacho de comandos de bloqueo de firewall via API de Wazuh `/active-response` tras aprobación HITL. | **Media (Fase 3)** |
| **6. GenAI Copilot con Vector DB (RAG)** | Base en Memoria | Indexación de documentos NIST SP 800-61 y MITRE ATT&CK en base vectorial (ChromaDB) con Gemini. | **Media** |
| **7. Modelo ML Entrenado & SHAP** | Heurística ponderada | Entrenamiento con dataset CIC-IDS2017, guardado en `.joblib` y explicabilidad matemática con SHAP. | **Media** |
| **8. Threat Intel con APIs Externas** | Cache local fijo | Consulta en tiempo real a las APIs de AbuseIPDB y base local MaxMind GeoIP2. | **Baja** |
| **9. Active Learning (Feedback Loop)** | Endpoint Mock | Pipeline de reentrenamiento que ajusta pesos de ML a partir de alertas marcadas como TP o FP. | **Baja** |

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

const API_BASE = '/api';

let currentAuthToken = null;

export function setAuthToken(token) {
  currentAuthToken = token;
}

export function getAuthToken() {
  return currentAuthToken;
}

function getHeaders(includeJson = true) {
  const headers = {};
  if (includeJson) {
    headers['Content-Type'] = 'application/json';
  }
  if (currentAuthToken) {
    headers['Authorization'] = `Bearer ${currentAuthToken}`;
  }
  return headers;
}

async function handleResponse(res, fallbackMsg) {
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const detail =
      (data && (typeof data.detail === 'string' ? data.detail : data.detail?.detail || data.error)) ||
      `${fallbackMsg} (HTTP ${res.status})`;
    const err = new Error(detail);
    err.status = res.status;
    err.payload = data;
    throw err;
  }
  return data;
}

// ============================================================================
// AUTENTICACIÓN Y GESTIÓN DE USUARIOS / ROLES (POSTGRESQL soc_users)
// ============================================================================

export async function loginUser(email, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await handleResponse(res, 'Error de autenticación');
  if (data.token) {
    setAuthToken(data.token);
  }
  return data;
}

export async function fetchCurrentUser() {
  const res = await fetch(`${API_BASE}/auth/me`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'Sesión inválida');
}

export async function fetchUsers() {
  const res = await fetch(`${API_BASE}/users`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo obtener la lista de usuarios de PostgreSQL');
}

export async function createUser(userPayload) {
  const res = await fetch(`${API_BASE}/users`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify(userPayload)
  });
  return await handleResponse(res, 'No se pudo crear el usuario en PostgreSQL');
}

export async function updateUser(userId, updatePayload) {
  const res = await fetch(`${API_BASE}/users/${userId}`, {
    method: 'PATCH',
    headers: getHeaders(true),
    body: JSON.stringify(updatePayload)
  });
  return await handleResponse(res, 'No se pudo actualizar el usuario');
}

export async function deleteUser(userId) {
  const res = await fetch(`${API_BASE}/users/${userId}`, {
    method: 'DELETE',
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo eliminar el usuario');
}

// ============================================================================
// SALUD DEL SISTEMA Y MÉTRICAS REALES (POSTGRESQL 15)
// ============================================================================

export async function fetchSystemHealth() {
  const res = await fetch(`${API_BASE}/system/health`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'Error verificando estado de microservicios');
}

export async function fetchMetrics() {
  const res = await fetch(`${API_BASE}/metrics`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'Error obteniendo métricas reales de PostgreSQL');
}

// ============================================================================
// ALERTAS E INCIDENTES (POSTGRESQL alerts)
// ============================================================================

export async function fetchAlerts(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== 'TODAS') params.set('severity', filters.severity);
  if (filters.status && filters.status !== 'TODOS') params.set('status', filters.status);
  if (filters.origin) params.set('origin', filters.origin);
  const qs = params.toString() ? `?${params.toString()}` : '';

  const res = await fetch(`${API_BASE}/alerts${qs}`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'Fallo al obtener alertas desde PostgreSQL');
}

export async function updateAlertStatus(alertId, status, notes = '') {
  const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId)}/status`, {
    method: 'PATCH',
    headers: getHeaders(true),
    body: JSON.stringify({ status, analyst_name: 'Operador SOC', notes })
  });
  return await handleResponse(res, 'No se pudo actualizar el estado de la alerta');
}

export async function deleteAlert(alertId) {
  const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId)}`, {
    method: 'DELETE',
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo eliminar la alerta');
}

export async function executeMitigation(alertId, action, target, analystName) {
  const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId)}/mitigate`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify({
      analyst_name: analystName,
      action,
      target,
      approved_by_human: true
    })
  });
  return await handleResponse(res, 'No se pudo ejecutar la mitigación Active Response');
}

export async function submitAlertFeedback(alertId, feedbackType, notes = '') {
  const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId)}/feedback`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify({
      analyst_name: 'Operador SOC',
      feedback: feedbackType,
      notes
    })
  });
  return await handleResponse(res, 'Fallo al registrar feedback en PostgreSQL');
}

// ============================================================================
// TELEMETRÍA WAZUH SIEM, TRÁFICO CONTINUO (FP/TN/TP) Y AUDITORÍA FORENSE
// ============================================================================

export async function fetchWazuhBuffer(limit = 100) {
  const res = await fetch(`${API_BASE}/wazuh/buffer?limit=${limit}`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo consultar wazuh_raw_events en PostgreSQL');
}

export async function escalateWazuhBufferEvent(eventId) {
  const res = await fetch(`${API_BASE}/wazuh/buffer/${encodeURIComponent(eventId)}/escalate`, {
    method: 'POST',
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo escalar el evento a alerta');
}

export async function fetchWazuhStatus() {
  const res = await fetch(`${API_BASE}/wazuh/status`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo consultar el estado de Wazuh SIEM');
}

export async function syncWazuhAlerts(limit = 25, minLevel = 3) {
  const res = await fetch(`${API_BASE}/wazuh/sync`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify({ limit, min_level: minLevel, escalate_anomalies: true })
  });
  return await handleResponse(res, 'Error sincronizando alertas desde Wazuh Indexer');
}

export async function fetchWazuhTrafficStatus() {
  const res = await fetch(`${API_BASE}/wazuh/traffic/status`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo consultar el estado del generador de tráfico Wazuh');
}

export async function toggleWazuhTraffic(enabled = null, intervalSeconds = 30) {
  const res = await fetch(`${API_BASE}/wazuh/traffic/toggle`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify({ enabled, interval_seconds: intervalSeconds })
  });
  return await handleResponse(res, 'Error cambiando estado de tráfico continuo Wazuh');
}

export async function emitWazuhRealisticTraffic(count = 3) {
  const res = await fetch(`${API_BASE}/wazuh/traffic/emit`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify({ count, escalate_to_alerts: true })
  });
  return await handleResponse(res, 'Error emitiendo lote de tráfico heterogéneo hacia Wazuh');
}

export async function fetchAuditLogs(limit = 150) {
  const res = await fetch(`${API_BASE}/audit-logs?limit=${limit}`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo consultar audit_logs en PostgreSQL');
}

// ============================================================================
// MACHINE LEARNING (modelo_soc.pkl), ACTIVE LEARNING Y THREAT INTEL
// ============================================================================

export async function fetchActiveLearningData() {
  const res = await fetch(`${API_BASE}/ml/active-learning`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo consultar el estado de Active Learning');
}

export async function triggerManualRetrain(payload = {}) {
  const res = await fetch(`${API_BASE}/ml/retrain`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify(payload)
  });
  return await handleResponse(res, 'Error al ejecutar el reentrenamiento de ML');
}

export async function predictUserLog(logPayload) {
  const res = await fetch(`${API_BASE}/predict/log`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify(logPayload)
  });
  return await handleResponse(res, 'Fallo en la predicción con modelo_soc.pkl');
}

export async function ingestLogEvent(logEvent) {
  const res = await fetch(`${API_BASE}/ingest`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify(logEvent)
  });
  return await handleResponse(res, 'Fallo al ingestar evento en el SIEM');
}

export async function fetchIpThreatIntel(ip) {
  const res = await fetch(`${API_BASE}/threat-intel/${encodeURIComponent(ip)}`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'No se pudo consultar Threat Intelligence');
}

// ============================================================================
// COPILOT IA (GOOGLE GEMINI + OLLAMA LOCAL FAILOVER)
// ============================================================================

export async function fetchCopilotStatus() {
  const res = await fetch(`${API_BASE}/copilot/status`, {
    headers: getHeaders(false)
  });
  return await handleResponse(res, 'Servicio Copilot fuera de línea');
}

export async function sendCopilotMessage(message, alertContext = null) {
  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: getHeaders(true),
    body: JSON.stringify({
      message,
      alert_context: alertContext
    })
  });
  return await handleResponse(res, 'Motores de IA (Gemini y Ollama) no disponibles');
}

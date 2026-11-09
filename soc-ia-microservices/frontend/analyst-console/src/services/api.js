const API_BASE = '/api';

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts`);
  if (!res.ok) {
    throw new Error(`Error ${res.status}: Fallo al obtener alertas del backend`);
  }
  return await res.json();
}

export async function sendCopilotMessage(message, alertContext = null, analystName = 'Analista SOC N1') {
  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message,
      alert_context: alertContext,
      analyst_name: analystName
    })
  });
  if (!res.ok) {
    throw new Error(`Error ${res.status}: Fallo en respuesta de Copilot`);
  }
  return await res.json();
}

export async function executeMitigation(alertId, action, target, analystName = 'Diego Aliaga') {
  const res = await fetch(`${API_BASE}/alerts/${alertId}/mitigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      analyst_name: analystName,
      action: action,
      target: target,
      approved_by_human: true
    })
  });
  if (!res.ok) {
    throw new Error(`Error ${res.status}: No se pudo ejecutar la mitigación`);
  }
  return await res.json();
}

export async function submitAlertFeedback(alertId, feedbackType, notes = '', analystName = 'Diego Aliaga') {
  const res = await fetch(`${API_BASE}/alerts/${alertId}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      analyst_name: analystName,
      feedback: feedbackType,
      notes: notes
    })
  });
  if (!res.ok) {
    throw new Error(`Error ${res.status}: Fallo al registrar feedback`);
  }
  return await res.json();
}

const API_BASE = '/api';

async function apiFetch(path, options = {}) {
  const session = JSON.parse(localStorage.getItem('soc_session') || 'null');
  const headers = new Headers(options.headers || {});
  if (path !== '/auth/login' && session?.token) {
    headers.set('Authorization', `Bearer ${session.token}`);
  }

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    let detail = `Error ${res.status}: solicitud fallida`;
    try {
      const body = await res.json();
      detail = body.detail || body.error || detail;
    } catch {
      // Keep the HTTP status when the server does not return JSON.
    }
    throw new Error(detail);
  }
  return await res.json();
}

export async function login(email, password, otp) {
  return apiFetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, otp })
  });
}

export async function fetchAlerts() {
  return apiFetch('/alerts');
}

export async function sendCopilotMessage(message, alertContext = null, analystName = 'Analista SOC N1') {
  return apiFetch('/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message,
      alert_context: alertContext,
      analyst_name: analystName
    })
  });
}

export async function executeMitigation(alertId, action, target, analystName = 'Diego Aliaga') {
  return apiFetch(`/alerts/${alertId}/mitigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      analyst_name: analystName,
      action: action,
      target: target,
      approved_by_human: true
    })
  });
}

export async function submitAlertFeedback(alertId, feedbackType, notes = '', analystName = 'Diego Aliaga') {
  return apiFetch(`/alerts/${alertId}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      analyst_name: analystName,
      feedback: feedbackType,
      notes: notes
    })
  });
}

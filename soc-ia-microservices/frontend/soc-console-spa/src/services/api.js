/**
 * Servicio centralizado de conexión con el API Gateway de FastAPI
 */

export const getAlerts = async () => {
  const response = await fetch('/api/alerts');
  if (!response.ok) throw new Error('Error al obtener alertas del SOC');
  return await response.json();
};

export const mitigateAlert = async (alertId, ip, analystName = 'Diego Aliaga') => {
  const response = await fetch(`/api/alerts/${alertId}/mitigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      analyst_name: analystName,
      action: 'BLOCK_IP',
      target: ip,
      approved_by_human: true,
    }),
  });
  if (!response.ok) throw new Error('Error al ejecutar orden de mitigación en Wazuh');
  return await response.json();
};

export const sendCopilotMessage = async (message, alertContext = null, analystName = 'Diego Aliaga') => {
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message,
      alert_context: alertContext,
      analyst_name: analystName,
    }),
  });
  if (!response.ok) throw new Error('Error en el servicio de GenAI Copilot');
  return await response.json();
};

export const checkHealth = async () => {
  const response = await fetch('/api/health');
  if (!response.ok) throw new Error('Gateway Offline');
  return await response.json();
};


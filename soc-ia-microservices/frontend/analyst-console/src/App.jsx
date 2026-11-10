import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import KpiCards from './components/KpiCards';
import AlertsTable from './components/AlertsTable';
import CopilotChat from './components/CopilotChat';
import MitigationModal from './components/MitigationModal';
import LogPredictorModal from './components/LogPredictorModal';
import Login from './components/Login';
import { fetchAlerts, sendCopilotMessage, executeMitigation, submitAlertFeedback } from './services/api';
import { RefreshCw, Sparkles, CheckCircle2, Brain } from 'lucide-react';

export default function App() {
  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const saved = localStorage.getItem('soc_session');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [activeAlert, setActiveAlert] = useState(null);
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    {
      sender: 'copilot',
      text: '👋 Bienvenido a la Consola de Operaciones SOC-IA. Selecciona cualquier alerta de la tabla y haz clic en "Investigar" para activar el triaje con MITRE ATT&CK y guías NIST SP 800-61.',
      timestamp: 'Sistema'
    }
  ]);
  const [isSendingChat, setIsSendingChat] = useState(false);
  const [mitigationAlert, setMitigationAlert] = useState(null);
  const [isMitigationOpen, setIsMitigationOpen] = useState(false);
  const [isPredictorOpen, setIsPredictorOpen] = useState(false);
  const [isExecutingMitigation, setIsExecutingMitigation] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    loadAlerts();
  };

  const handleLogout = () => {
    localStorage.removeItem('soc_session');
    setCurrentUser(null);
  };

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const loadAlerts = async () => {
    try {
      setIsRefreshing(true);
      const data = await fetchAlerts();
      setAlerts(data.alerts || []);
    } catch (err) {
      console.error('Error cargando alertas:', err);
      // Fallback con datos de demostración si el backend aún no está corriendo
      setAlerts([
        {
          alert_id: 'ALT-10023',
          severity: 'CRÍTICA',
          status: 'NUEVA',
          raw_event: {
            user: 'admin',
            source_ip: '185.220.101.5',
            source_system: 'Portal Web Dummy',
            status: 'FAILURE'
          },
          ml_score: { risk_score: 92.5 },
          mitre_attack: ['T1110 - Brute Force']
        },
        {
          alert_id: 'ALT-10024',
          severity: 'ALTA',
          status: 'EN_INVESTIGACION',
          raw_event: {
            user: 'daliaga',
            source_ip: '190.236.14.82',
            source_system: 'SSH',
            status: 'SUCCESS'
          },
          ml_score: { risk_score: 74.0 },
          mitre_attack: ['T1078 - Valid Accounts']
        }
      ]);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const handleInvestigate = async (alert) => {
    setActiveAlert(alert);
    setIsChatOpen(true);

    const promptText = `Investigar la alerta ${alert.alert_id} asociada al usuario "${alert.raw_event?.user}" desde la IP ${alert.raw_event?.source_ip}.`;
    
    // Agrega el mensaje del analista
    setChatMessages((prev) => [
      ...prev,
      { sender: 'user', text: promptText, timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
    ]);

    setIsSendingChat(true);
    try {
      const response = await sendCopilotMessage(promptText, alert);
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: response.reply,
          recommended_action: response.recommended_action,
          target: response.target,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } catch (err) {
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: `⚠️ No se pudo conectar con el microservicio de Copilot (puerto 8004). Verifica que los contenedores estén activos.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setIsSendingChat(false);
    }
  };

  const handleSendMessage = async (text) => {
    setChatMessages((prev) => [
      ...prev,
      { sender: 'user', text, timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
    ]);

    setIsSendingChat(true);
    try {
      const response = await sendCopilotMessage(text, activeAlert);
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: response.reply,
          recommended_action: response.recommended_action,
          target: response.target,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } catch (err) {
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: `Error de comunicación con el Copilot: ${err.message}`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setIsSendingChat(false);
    }
  };

  const handleOpenMitigation = (alert) => {
    setMitigationAlert(alert);
    setIsMitigationOpen(true);
  };

  const handleTriggerMitigationFromChat = (action, target) => {
    if (activeAlert) {
      setMitigationAlert(activeAlert);
      setIsMitigationOpen(true);
    }
  };

  const handleConfirmMitigation = async ({ alertId, action, target, analystName }) => {
    setIsExecutingMitigation(true);
    try {
      await executeMitigation(alertId, action, target, analystName);
      
      // Actualizar estado local
      setAlerts((prev) =>
        prev.map((a) =>
          a.alert_id === alertId
            ? { ...a, status: 'CONTENIDA', mitigation_status: `EJECUTADA (${action} on ${target})` }
            : a
        )
      );

      setIsMitigationOpen(false);
      showToast(`✅ Active Response despachado: IP ${target} bloqueada por ${analystName}`);

      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: `🛡️ **Mitigación Ejecutada con Éxito:** Se ha emitido la orden de bloqueo en Wazuh Firewall para el host \`${target}\`. Registrado en logs de auditoría forense.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } catch (err) {
      alert(`Error al mitigar: ${err.message}`);
    } finally {
      setIsExecutingMitigation(false);
    }
  };

  const handleFeedback = async (alertId, feedbackType) => {
    try {
      await submitAlertFeedback(alertId, feedbackType);
      showToast(`Feedback registrado (${feedbackType === 'VERDADERO_POSITIVO' ? 'TP' : 'FP'}). El modelo ML ajustará sus pesos.`);
    } catch (err) {
      showToast(`Error al enviar feedback: ${err.message}`);
    }
  };

  if (!currentUser) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col">
      <Navbar
        onRefresh={loadAlerts}
        isRefreshing={isRefreshing}
        currentUser={currentUser}
        onLogout={handleLogout}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {/* Top Actions Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">Centro de Detección & Respuesta</h2>
            <p className="text-xs text-slate-400">
              Supervisión en tiempo real de eventos de autenticación sospechosos
            </p>
          </div>
          <div className="flex items-center gap-2.5">
            <button
              onClick={loadAlerts}
              disabled={isRefreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-blue-400' : ''}`} />
              <span>Actualizar Alertas</span>
            </button>
            <button
              onClick={() => setIsPredictorOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white text-xs font-bold shadow-lg shadow-purple-500/25 transition-all hover:scale-[1.02]"
              title="Analizador y predictor de logs en vivo con modelo_soc.pkl"
            >
              <Brain className="w-3.5 h-3.5" />
              <span>Predecir Logs (modelo_soc)</span>
            </button>
            <button
              onClick={() => setIsChatOpen(!isChatOpen)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5 text-blue-400" />
              <span>Abrir Copilot</span>
            </button>
          </div>
        </div>

        {/* KPIs */}
        <KpiCards alerts={alerts} />

        {/* Alertas Table */}
        <AlertsTable
          alerts={alerts}
          onInvestigate={handleInvestigate}
          onOpenMitigation={handleOpenMitigation}
          onFeedback={handleFeedback}
          loading={loading}
        />
      </main>

      {/* Chat Drawer */}
      <CopilotChat
        isOpen={isChatOpen}
        onClose={() => setIsChatOpen(false)}
        activeAlert={activeAlert}
        messages={chatMessages}
        onSendMessage={handleSendMessage}
        onTriggerMitigation={handleTriggerMitigationFromChat}
        isSending={isSendingChat}
      />

            {/* Human-in-the-Loop Mitigation Modal */}
      <MitigationModal
        isOpen={isMitigationOpen}
        onClose={() => setIsMitigationOpen(false)}
        alert={mitigationAlert}
        onConfirm={handleConfirmMitigation}
        isExecuting={isExecutingMitigation}
      />

      {/* Log Predictor Modal with modelo_soc.pkl */}
      <LogPredictorModal
        isOpen={isPredictorOpen}
        onClose={() => setIsPredictorOpen(false)}
        onEscalateToAlert={(alertPayload, predResult) => {
          showToast(`🚨 Alerta escalada al SOC para el usuario "${alertPayload.user}" (Score: ${predResult.risk_score}%)`);
          loadAlerts();
        }}
        onInvestigateInCopilot={(simulatedAlert) => {
          handleInvestigate(simulatedAlert);
        }}
      />

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 left-1/2 -translate-x-1/2 bg-slate-900 border border-slate-700 text-white px-4 py-2.5 rounded-2xl shadow-2xl flex items-center gap-2 text-xs font-medium z-50 animate-in fade-in slide-in-from-bottom-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}

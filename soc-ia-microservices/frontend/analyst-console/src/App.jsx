import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import KpiCards from './components/KpiCards';
import AlertsTable from './components/AlertsTable';
import CopilotChat from './components/CopilotChat';
import MitigationModal from './components/MitigationModal';
import LogPredictorModal from './components/LogPredictorModal';
import UsersManagementPanel from './components/UsersManagementPanel';
import WazuhTelemetryPanel from './components/WazuhTelemetryPanel';
import AuditAndMlPanel from './components/AuditAndMlPanel';
import Login from './components/Login';
import {
  setAuthToken,
  fetchAlerts,
  fetchMetrics,
  fetchSystemHealth,
  fetchCopilotStatus,
  sendCopilotMessage,
  executeMitigation,
  submitAlertFeedback,
  updateAlertStatus,
  deleteAlert,
  syncWazuhAlerts,
  emitWazuhRealisticTraffic
} from './services/api';
import {
  RefreshCw,
  Sparkles,
  CheckCircle2,
  Brain,
  ShieldAlert,
  Radio,
  FileText,
  Users,
  AlertTriangle,
  Zap,
  Clock
} from 'lucide-react';

export default function App() {
  // SIEMPRE inicia en null para exigir inicio de sesión obligatorio en cada carga
  const [currentUser, setCurrentUser] = useState(null);
  const [activeModule, setActiveModule] = useState('incidents'); // 'incidents' | 'wazuh' | 'ml' | 'audit' | 'users'

  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  const [copilotStatus, setCopilotStatus] = useState(null);
  const [backendError, setBackendError] = useState(null);

  const [loading, setLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isSyncingWazuh, setIsSyncingWazuh] = useState(false);
  const [isEmittingTraffic, setIsEmittingTraffic] = useState(false);

  // Auto-refresh cada 30 segundos sincronizado con el generador de tráfico realista hacia Wazuh
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [secondsLeft, setSecondsLeft] = useState(30);

  const [activeAlert, setActiveAlert] = useState(null);
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [isSendingChat, setIsSendingChat] = useState(false);

  const [mitigationAlert, setMitigationAlert] = useState(null);
  const [isMitigationOpen, setIsMitigationOpen] = useState(false);
  const [isPredictorOpen, setIsPredictorOpen] = useState(false);
  const [isExecutingMitigation, setIsExecutingMitigation] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  // Limpiar cualquier sesión heredada en localStorage al abrir la app
  useEffect(() => {
    try {
      localStorage.removeItem('soc_session');
    } catch {
      // ignore
    }
  }, []);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4500);
  };

  const handleLogout = useCallback(() => {
    setAuthToken(null);
    setCurrentUser(null);
    setAlerts([]);
    setMetrics(null);
    setActiveAlert(null);
    setIsChatOpen(false);
  }, []);

  const loadDashboardData = useCallback(async () => {
    setIsRefreshing(true);
    setBackendError(null);
    try {
      const [alertsData, metricsData, healthData, copilotData] = await Promise.all([
        fetchAlerts(),
        fetchMetrics().catch(() => null),
        fetchSystemHealth().catch(() => null),
        fetchCopilotStatus().catch(() => null)
      ]);
      setAlerts(alertsData.alerts || []);
      if (metricsData) setMetrics(metricsData);
      if (healthData) setSystemHealth(healthData);
      if (copilotData) setCopilotStatus(copilotData);
      setSecondsLeft(30);
    } catch (err) {
      if (err.status === 401) {
        handleLogout();
        return;
      }
      setBackendError(err.message || 'No se pudo conectar con PostgreSQL / API Gateway.');
      setAlerts([]);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, [handleLogout]);

  // Temporizador de actualización automática cada 30 segundos cuando hay sesión activa
  useEffect(() => {
    if (!currentUser || !autoRefreshEnabled) return;

    const timer = setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev <= 1) {
          loadDashboardData();
          return 30;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [currentUser, autoRefreshEnabled, loadDashboardData]);

  const handleLoginSuccess = async (user) => {
    setCurrentUser(user);
    setLoading(true);
    setChatMessages([
      {
        sender: 'copilot',
        text: `Hola ${user.name} (${user.role}). Puedes investigar cualquier alerta con "Investigar" y se abrirá este mini pop-up inteligente a la derecha sin bloquear tus botones. Primero te explicaré la causa y evaluación FP/TP, y si pides solucionarlo habilitaré la acción de mitigación.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);
    await loadDashboardData();
  };

  const handleQuickWazuhSync = async () => {
    setIsSyncingWazuh(true);
    try {
      const res = await syncWazuhAlerts(25, 3);
      showToast(
        `📡 Sincronizados ${res.fetched_and_evaluated} eventos de Wazuh Indexer (${res.escalated_to_alerts} alertas activas)`
      );
      await loadDashboardData();
    } catch (err) {
      showToast(`⚠️ Error sincronizando Wazuh: ${err.message}`);
    } finally {
      setIsSyncingWazuh(false);
    }
  };

  const handleEmitRealisticTraffic = async () => {
    setIsEmittingTraffic(true);
    try {
      const res = await emitWazuhRealisticTraffic(3);
      const summary = (res.events || [])
        .map((e) => `${e.user} (${e.scenario_type})`)
        .join(', ');
      showToast(`⚡ Tráfico diverso inyectado en Wazuh y evaluado por ML: ${summary}`);
      await loadDashboardData();
    } catch (err) {
      showToast(`⚠️ Error generando tráfico Wazuh: ${err.message}`);
    } finally {
      setIsEmittingTraffic(false);
    }
  };

  // Paso 1 Progresivo: Al hacer clic en "Investigar", abre el mini pop-up y explica la causa
  const handleInvestigate = async (alert) => {
    setActiveAlert(alert);
    setIsChatOpen(true);

    const promptText = `Explica a qué se debe la alerta ${alert.alert_id} ("${alert.title}") del usuario "${alert.raw_event?.user}" desde la IP ${alert.raw_event?.source_ip}, y evalúa si podría ser un Falso Positivo o un Verdadero Positivo.`;

    setChatMessages((prev) => [
      ...prev,
      {
        sender: 'user',
        text: promptText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);

    setIsSendingChat(true);
    try {
      const response = await sendCopilotMessage(promptText, alert);
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: response.reply,
          provider: response.provider,
          model: response.model,
          intent_mode: response.intent_mode,
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
          isError: true,
          text: `${err.message}`,
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
      {
        sender: 'user',
        text,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);

    setIsSendingChat(true);
    try {
      const response = await sendCopilotMessage(text, activeAlert);
      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: response.reply,
          provider: response.provider,
          model: response.model,
          intent_mode: response.intent_mode,
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
          isError: true,
          text: `${err.message}`,
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

  const handleTriggerMitigationFromChat = () => {
    if (activeAlert) {
      setMitigationAlert(activeAlert);
      setIsMitigationOpen(true);
    }
  };

  const handleConfirmMitigation = async ({ alertId, action, target, analystName }) => {
    setIsExecutingMitigation(true);
    try {
      const res = await executeMitigation(alertId, action, target, analystName);
      setIsMitigationOpen(false);
      showToast(`🛡️ Active Response ejecutado (${action} sobre ${target}) y auditado en PostgreSQL`);

      setChatMessages((prev) => [
        ...prev,
        {
          sender: 'copilot',
          text: `🛡️ **Mitigación Registrada en PostgreSQL & Wazuh:** Acción \`${action}\` sobre \`${target}\` firmada por \`${analystName}\`. Estado Wazuh: \`${res.wazuh_result?.status || 'PROCESSED'}\`.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
      await loadDashboardData();
    } catch (err) {
      showToast(`⚠️ Error al mitigar: ${err.message}`);
    } finally {
      setIsExecutingMitigation(false);
    }
  };

  const handleFeedback = async (alertId, feedbackType) => {
    try {
      const res = await submitAlertFeedback(alertId, feedbackType);
      const newThresh = res.active_learning?.new_threshold_soc_model;
      showToast(
        `✅ Feedback ${feedbackType === 'VERDADERO_POSITIVO' ? 'TP' : 'FP'} guardado en PostgreSQL${
          newThresh ? ` (Nuevo umbral ML: ${newThresh}%)` : ''
        }`
      );
      await loadDashboardData();
    } catch (err) {
      showToast(`⚠️ Error al enviar feedback: ${err.message}`);
    }
  };

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      showToast(`✅ Estado de alerta ${alertId} actualizado a ${newStatus} en PostgreSQL`);
      await loadDashboardData();
    } catch (err) {
      showToast(`⚠️ Error al cambiar estado: ${err.message}`);
    }
  };

  const handleDeleteAlert = async (alertId) => {
    if (!window.confirm(`¿Eliminar permanentemente la alerta ${alertId} de PostgreSQL?`)) return;
    try {
      await deleteAlert(alertId);
      showToast(`🗑️ Alerta ${alertId} eliminada de PostgreSQL`);
      await loadDashboardData();
    } catch (err) {
      showToast(`⚠️ Error al eliminar alerta: ${err.message}`);
    }
  };

  // Puerta de Autenticación Obligatoria
  if (!currentUser) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  const navTabs = [
    { id: 'incidents', label: 'Incidentes & Triaje', icon: ShieldAlert, count: alerts.length },
    {
      id: 'wazuh',
      label: 'Telemetría Wazuh SIEM',
      icon: Radio,
      count: metrics?.wazuh_buffer_total ?? 0
    },
    {
      id: 'ml',
      label: 'Motor ML & Active Learning',
      icon: Brain,
      count: metrics?.ml_feedback?.total ?? 0
    },
    {
      id: 'audit',
      label: 'Bitácora Forense (audit_logs)',
      icon: FileText,
      count: metrics?.audit_logs_total ?? 0
    },
    {
      id: 'users',
      label: 'Usuarios & Roles RBAC',
      icon: Users,
      count: metrics?.active_users ?? 0
    }
  ];

  const renderActiveModuleContent = () => {
    switch (activeModule) {
      case 'incidents':
        return (
          <AlertsTable
            alerts={alerts}
            currentUser={currentUser}
            activeAlertId={activeAlert?.alert_id}
            onInvestigate={handleInvestigate}
            onOpenMitigation={handleOpenMitigation}
            onFeedback={handleFeedback}
            onStatusChange={handleStatusChange}
            onDeleteAlert={handleDeleteAlert}
            loading={loading}
          />
        );
      case 'wazuh':
        return (
          <WazuhTelemetryPanel
            currentUser={currentUser}
            onNotify={showToast}
            onAlertsUpdated={loadDashboardData}
          />
        );
      case 'ml':
        return (
          <AuditAndMlPanel
            mode="ml"
            currentUser={currentUser}
            onNotify={showToast}
            onOpenPredictor={() => setIsPredictorOpen(true)}
          />
        );
      case 'audit':
        return (
          <AuditAndMlPanel
            mode="audit"
            currentUser={currentUser}
            onNotify={showToast}
            onOpenPredictor={() => setIsPredictorOpen(true)}
          />
        );
      case 'users':
        return (
          <UsersManagementPanel
            currentUser={currentUser}
            onNotify={(msg) => {
              showToast(msg);
              loadDashboardData();
            }}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col">
      <Navbar
        currentUser={currentUser}
        onLogout={handleLogout}
        systemHealth={systemHealth}
      />

      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4 sm:p-6 pb-28">
        {/* Top Action Bar */}
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 mb-5">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2.5">
              <span>Centro de Operaciones de Seguridad (SOC-IA)</span>
              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                <Clock className="w-3 h-3" />
                {autoRefreshEnabled ? `Auto-actualización: ${secondsLeft}s` : 'Auto-refresh pausado'}
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Tráfico continuo en vivo hacia Wazuh SIEM (Falsos Positivos, Verdaderos Negativos y Ataques Reales) evaluado cada 30s por{' '}
              <code className="text-purple-400">modelo_soc.pkl</code>
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Botón Actualizar + Toggle 30s */}
            <button
              onClick={loadDashboardData}
              disabled={isRefreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors cursor-pointer"
              title="Actualizar tabla de alertas ahora mismo"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-blue-400' : ''}`} />
              <span>Actualizar ({secondsLeft}s)</span>
            </button>

            <button
              onClick={() => setAutoRefreshEnabled(!autoRefreshEnabled)}
              className={`px-2.5 py-1.5 rounded-xl text-[11px] font-semibold border transition-colors cursor-pointer ${
                autoRefreshEnabled
                  ? 'bg-emerald-950/50 text-emerald-300 border-emerald-500/30 hover:bg-emerald-900/50'
                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
              }`}
              title="Activar o pausar el refresco automático cada 30 segundos"
            >
              {autoRefreshEnabled ? '⏱️ 30s ON' : '⏸️ 30s OFF'}
            </button>

            {currentUser.role !== 'AUDITOR' && (
              <>
                <button
                  onClick={handleEmitRealisticTraffic}
                  disabled={isEmittingTraffic}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 text-xs font-semibold transition-colors cursor-pointer"
                  title="Inyectar lote de logs variados (Posible Falso Positivo, Verdadero Negativo y Ataque Real) al pipeline Wazuh"
                >
                  <Zap className={`w-3.5 h-3.5 ${isEmittingTraffic ? 'animate-bounce' : ''}`} />
                  <span>
                    {isEmittingTraffic ? 'Inyectando Logs...' : 'Simular Tráfico Realista (FP / TN / TP)'}
                  </span>
                </button>

                <button
                  onClick={handleQuickWazuhSync}
                  disabled={isSyncingWazuh}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-semibold transition-colors cursor-pointer"
                  title="Extraer alertas desde Wazuh Indexer (:9200)"
                >
                  <Radio className={`w-3.5 h-3.5 ${isSyncingWazuh ? 'animate-spin' : ''}`} />
                  <span>{isSyncingWazuh ? 'Sincronizando...' : 'Sincronizar Wazuh'}</span>
                </button>
              </>
            )}

            <button
              onClick={() => setIsPredictorOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white text-xs font-bold shadow-lg shadow-purple-500/25 transition-all cursor-pointer"
            >
              <Brain className="w-3.5 h-3.5" />
              <span>Predecir Logs (modelo_soc)</span>
            </button>

            {/* Botón de Copilot IA */}
            <button
              onClick={() => setIsChatOpen(!isChatOpen)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-colors cursor-pointer ${
                isChatOpen
                  ? 'bg-purple-600 text-white border-purple-500 shadow-lg shadow-purple-600/25'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{isChatOpen ? 'Cerrar Copilot IA' : 'Abrir Copilot IA'}</span>
            </button>
          </div>
        </div>

        {/* Real Operational Error Banner (if backend is down) */}
        {backendError && (
          <div className="mb-5 p-4 rounded-2xl bg-rose-950/60 border border-rose-500/40 text-rose-200 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              <span>
                <strong>Error de Conexión en Producción:</strong> {backendError}
              </span>
            </div>
            <button
              onClick={loadDashboardData}
              className="px-3 py-1 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold cursor-pointer"
            >
              Reintentar
            </button>
          </div>
        )}

        {/* KPI Cards from PostgreSQL */}
        <KpiCards alerts={alerts} metrics={metrics} />

        {/* Module Navigation Tabs */}
        <div className="flex items-center gap-2 overflow-x-auto pb-3 mb-5 border-b border-slate-800">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const active = activeModule === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveModule(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold whitespace-nowrap transition-all cursor-pointer ${
                  active
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/25'
                    : 'bg-slate-900/70 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                    active ? 'bg-blue-800 text-white' : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Contenido Principal: Ocupa el 100% del ancho con espacio limpio sin compresiones */}
        <div className="w-full">
          {renderActiveModuleContent()}
        </div>
      </main>

      {/* Mini Pop-Up Inteligente de Copilot IA en la Esquina Inferior Derecha (Minimizable y Flotante) */}
      <CopilotChat
        isOpen={isChatOpen}
        onClose={() => setIsChatOpen(false)}
        activeAlert={activeAlert}
        messages={chatMessages}
        onSendMessage={handleSendMessage}
        onTriggerMitigation={handleTriggerMitigationFromChat}
        isSending={isSendingChat}
        copilotStatus={copilotStatus}
      />

      {/* Human-in-the-Loop Mitigation Modal */}
      <MitigationModal
        isOpen={isMitigationOpen}
        onClose={() => setIsMitigationOpen(false)}
        alert={mitigationAlert}
        currentUser={currentUser}
        onConfirm={handleConfirmMitigation}
        isExecuting={isExecutingMitigation}
      />

      {/* Log Predictor Modal with modelo_soc.pkl */}
      <LogPredictorModal
        isOpen={isPredictorOpen}
        onClose={() => setIsPredictorOpen(false)}
        onEscalateToAlert={(alertPayload, predResult) => {
          showToast(
            `🚨 Alerta guardada en PostgreSQL para "${alertPayload.user}" (Score: ${predResult.risk_score}%)`
          );
          loadDashboardData();
        }}
        onInvestigateInCopilot={(alertFromPredictor) => {
          handleInvestigate(alertFromPredictor);
        }}
      />

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 left-1/2 -translate-x-1/2 bg-slate-900 border border-slate-700 text-white px-4 py-2.5 rounded-2xl shadow-2xl flex items-center gap-2 text-xs font-medium z-50 animate-in fade-in slide-in-from-bottom-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}

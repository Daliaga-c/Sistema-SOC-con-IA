import React, { useState } from 'react';
import {
  Search,
  ShieldBan,
  Sparkles,
  Filter,
  CheckCircle,
  XCircle,
  Eye,
  Trash2,
  Download,
  Globe,
  X,
  Terminal,
  Tag
} from 'lucide-react';
import { fetchIpThreatIntel } from '../services/api';

export default function AlertsTable({
  alerts = [],
  currentUser,
  activeAlertId,
  onInvestigate,
  onOpenMitigation,
  onFeedback,
  onStatusChange,
  onDeleteAlert,
  loading = false
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('TODAS');
  const [filterStatus, setFilterStatus] = useState('TODOS');
  const [filterScenario, setFilterScenario] = useState('TODOS');
  const [inspectAlert, setInspectAlert] = useState(null);
  const [inspectThreatIntel, setInspectThreatIntel] = useState(null);
  const [loadingTi, setLoadingTi] = useState(false);

  const userRole = currentUser?.role || 'ANALISTA_L1';
  const canMitigate = userRole === 'ADMIN_SOC' || userRole === 'ANALISTA_L2';
  const canEditStatus = userRole !== 'AUDITOR';
  const isAdmin = userRole === 'ADMIN_SOC';

  // Infiere el escenario si proviene de Wazuh o del generador de tráfico realista
  const getScenarioInfo = (alert) => {
    const explicitType = alert.raw_event?.metadata?.scenario_type;
    const contextNote = alert.raw_event?.metadata?.context_note;
    const risk = alert.ml_score?.risk_score || 0;

    if (explicitType === 'POSIBLE_FALSO_POSITIVO' || alert.status === 'CERRADA_FP') {
      return {
        code: 'POSIBLE_FALSO_POSITIVO',
        label: 'Posible Falso Positivo (FP)',
        style: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
        note: contextNote || 'Actividad operativa inusual pero potencialmente legítima (verificar con usuario)'
      };
    }
    if (explicitType === 'VERDADERO_NEGATIVO' || (risk < 45 && alert.severity === 'BAJA')) {
      return {
        code: 'VERDADERO_NEGATIVO',
        label: 'Verdadero Negativo (Normal)',
        style: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
        note: contextNote || 'Tráfico corporativo benigno dentro de parámetros normales'
      };
    }
    return {
      code: 'VERDADERO_POSITIVO',
      label: 'Amenaza / Verdadero Positivo',
      style: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
      note: contextNote || 'Patrón de ataque o anomalía crítica detectada por Wazuh y modelo_soc.pkl'
    };
  };

  const filtered = alerts.filter((alert) => {
    const user = alert.raw_event?.user || '';
    const ip = alert.raw_event?.source_ip || '';
    const id = alert.alert_id || '';
    const title = alert.title || '';
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      user.toLowerCase().includes(term) ||
      ip.toLowerCase().includes(term) ||
      id.toLowerCase().includes(term) ||
      title.toLowerCase().includes(term);

    const matchesSeverity = filterSeverity === 'TODAS' || alert.severity === filterSeverity;
    const matchesStatus = filterStatus === 'TODOS' || alert.status === filterStatus;
    const scenarioInfo = getScenarioInfo(alert);
    const matchesScenario = filterScenario === 'TODOS' || scenarioInfo.code === filterScenario;
    return matchesSearch && matchesSeverity && matchesStatus && matchesScenario;
  });

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRÍTICA':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'ALTA':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'MEDIA':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  const handleOpenInspect = async (alert) => {
    setInspectAlert(alert);
    setInspectThreatIntel(null);
    const ip = alert.raw_event?.source_ip;
    if (ip && ip !== 'N/A') {
      setLoadingTi(true);
      try {
        const ti = await fetchIpThreatIntel(ip);
        setInspectThreatIntel(ti);
      } catch {
        setInspectThreatIntel(null);
      } finally {
        setLoadingTi(false);
      }
    }
  };

  const handleExportCsv = () => {
    if (filtered.length === 0) return;
    const headers = [
      'alert_id',
      'created_at',
      'title',
      'scenario_type',
      'severity',
      'status',
      'user',
      'source_ip',
      'risk_score',
      'mitigation_status'
    ];
    const rows = filtered.map((a) => [
      a.alert_id,
      a.created_at || '',
      `"${(a.title || '').replace(/"/g, '""')}"`,
      getScenarioInfo(a).code,
      a.severity,
      a.status,
      a.raw_event?.user || '',
      a.raw_event?.source_ip || '',
      a.ml_score?.risk_score ?? 0,
      `"${(a.mitigation_status || '').replace(/"/g, '""')}"`
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `soc_ia_alerts_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <>
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-xl shadow-black/30">
        {/* Table Header / Filters Bar */}
        <div className="p-4 border-b border-slate-800/80 flex flex-col xl:flex-row xl:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-white tracking-wide">
              Alertas e Incidentes en Tiempo Real (<code className="text-blue-400">alerts</code>)
            </h2>
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
              {filtered.length}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search Box */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Buscar IP, usuario, regla o ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-950/60 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors w-44 sm:w-52"
              />
            </div>

            {/* Scenario Filter (TP / FP / TN) */}
            <div className="flex items-center gap-1 bg-slate-950/60 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs">
              <Tag className="w-3 h-3 text-purple-400" />
              <select
                value={filterScenario}
                onChange={(e) => setFilterScenario(e.target.value)}
                className="bg-transparent text-slate-300 text-xs focus:outline-none cursor-pointer"
              >
                <option value="TODOS" className="bg-slate-900">Todos los Escenarios (TP/FP/TN)</option>
                <option value="VERDADERO_POSITIVO" className="bg-slate-900">Amenaza Real (TP)</option>
                <option value="POSIBLE_FALSO_POSITIVO" className="bg-slate-900">Posible Falso Positivo (FP)</option>
                <option value="VERDADERO_NEGATIVO" className="bg-slate-900">Verdadero Negativo (Normal)</option>
              </select>
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1 bg-slate-950/60 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs">
              <Filter className="w-3 h-3 text-slate-400" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="bg-transparent text-slate-300 text-xs focus:outline-none cursor-pointer"
              >
                <option value="TODAS" className="bg-slate-900">Severidad: Todas</option>
                <option value="CRÍTICA" className="bg-slate-900">Crítica</option>
                <option value="ALTA" className="bg-slate-900">Alta</option>
                <option value="MEDIA" className="bg-slate-900">Media</option>
                <option value="BAJA" className="bg-slate-900">Baja</option>
              </select>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-1 bg-slate-950/60 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs">
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="bg-transparent text-slate-300 text-xs focus:outline-none cursor-pointer"
              >
                <option value="TODOS" className="bg-slate-900">Estado: Todos</option>
                <option value="NUEVA" className="bg-slate-900">NUEVA</option>
                <option value="EN_INVESTIGACION" className="bg-slate-900">EN_INVESTIGACION</option>
                <option value="CONTENIDA" className="bg-slate-900">CONTENIDA</option>
                <option value="CERRADA_TP" className="bg-slate-900">CERRADA_TP</option>
                <option value="CERRADA_FP" className="bg-slate-900">CERRADA_FP</option>
                <option value="DESCARTADA" className="bg-slate-900">DESCARTADA</option>
              </select>
            </div>

            {/* Export CSV */}
            <button
              onClick={handleExportCsv}
              disabled={filtered.length === 0}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors cursor-pointer"
              title="Exportar alertas actuales de PostgreSQL a CSV"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span>CSV</span>
            </button>
          </div>
        </div>

        {/* Table Body con Scroll Horizontal y Columna de Acciones Sticky */}
        <div className="overflow-x-auto relative">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-950/70 text-slate-400 font-semibold border-b border-slate-800/80 uppercase tracking-wider text-[10px]">
              <tr>
                <th className="py-3 px-3.5 min-w-[110px]">ID / Fecha</th>
                <th className="py-3 px-3.5 min-w-[240px]">Título / Escenario de Tráfico</th>
                <th className="py-3 px-3.5 min-w-[130px]">Usuario / IP</th>
                <th className="py-3 px-3.5 min-w-[85px]">Severidad</th>
                <th className="py-3 px-3.5 min-w-[95px]">Score ML</th>
                <th className="py-3 px-3.5 min-w-[135px]">Estado</th>
                <th className="py-3 px-3.5 text-right sticky right-0 bg-slate-950/95 backdrop-blur-md z-20 shadow-[-8px_0_12px_-2px_rgba(0,0,0,0.6)] whitespace-nowrap min-w-[220px]">
                  Acciones Operativas
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {loading ? (
                <tr>
                  <td colSpan="7" className="py-10 text-center text-slate-400">
                    Consultando tabla <code className="text-blue-400">alerts</code> en PostgreSQL 15...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-10 text-center text-slate-400">
                    No hay alertas para los filtros seleccionados. Usa <strong>"Emitir Tráfico Realista (FP/TN/TP)"</strong> o espera la actualización automática cada 30s.
                  </td>
                </tr>
              ) : (
                filtered.map((alert) => {
                  const risk = alert.ml_score?.risk_score || 0;
                  const isContained =
                    alert.status === 'CONTENIDA' || alert.mitigation_status?.includes('EJECUTADA');
                  const scenario = getScenarioInfo(alert);
                  const isSelected = activeAlertId === alert.alert_id;

                  return (
                    <tr
                      key={alert.alert_id}
                      className={`transition-colors group ${
                        isSelected
                          ? 'bg-blue-950/40 border-l-2 border-l-blue-500'
                          : 'hover:bg-slate-800/35'
                      }`}
                    >
                      <td className="py-3 px-3.5">
                        <div className="font-mono font-bold text-slate-200">{alert.alert_id}</div>
                        <div className="text-[10px] text-slate-500">
                          {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : 'Ahora'}
                        </div>
                      </td>
                      <td className="py-3 px-3.5">
                        <div className="font-semibold text-white max-w-sm truncate" title={alert.title}>
                          {alert.title}
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5 mt-1">
                          <span
                            className={`text-[9px] font-bold px-2 py-0.5 rounded-md border ${scenario.style}`}
                            title={scenario.note}
                          >
                            {scenario.label}
                          </span>
                          <span className="text-[10px] text-slate-400 truncate max-w-[200px]" title={scenario.note}>
                            {scenario.note}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-3.5">
                        <div className="font-semibold text-blue-300">{alert.raw_event?.user || 'N/A'}</div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {alert.raw_event?.source_ip || 'N/A'}
                        </div>
                      </td>
                      <td className="py-3 px-3.5">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadge(
                            alert.severity
                          )}`}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3.5">
                        <div className="flex items-center gap-1.5">
                          <div className="w-12 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                risk >= 80
                                  ? 'bg-rose-500'
                                  : risk >= 55
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{ width: `${Math.min(risk, 100)}%` }}
                            />
                          </div>
                          <span className="font-mono font-bold text-slate-200">{risk}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-3.5">
                        {canEditStatus ? (
                          <select
                            value={alert.status || 'NUEVA'}
                            onChange={(e) => onStatusChange(alert.alert_id, e.target.value)}
                            className="bg-slate-950 border border-slate-700/80 rounded-lg px-2 py-1 text-[10px] font-semibold text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer"
                          >
                            <option value="NUEVA">NUEVA</option>
                            <option value="EN_INVESTIGACION">EN_INVESTIGACION</option>
                            <option value="CONTENIDA">CONTENIDA</option>
                            <option value="CERRADA_TP">CERRADA_TP</option>
                            <option value="CERRADA_FP">CERRADA_FP</option>
                            <option value="DESCARTADA">DESCARTADA</option>
                          </select>
                        ) : (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            {alert.status}
                          </span>
                        )}
                      </td>
                      {/* Columna Sticky Right: SIEMPRE visible y jamás tapada ni cortada */}
                      <td
                        className={`py-3 px-3.5 text-right sticky right-0 backdrop-blur-md z-10 shadow-[-8px_0_12px_-2px_rgba(0,0,0,0.6)] whitespace-nowrap ${
                          isSelected ? 'bg-slate-900/95' : 'bg-slate-900/90 group-hover:bg-slate-900/95'
                        }`}
                      >
                        <div className="flex items-center justify-end gap-1">
                          {/* Inspeccionar JSONB & Threat Intel */}
                          <button
                            onClick={() => handleOpenInspect(alert)}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors cursor-pointer"
                            title="Ver Detalle Forense JSONB y Threat Intelligence"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>

                          {/* Investigar con IA */}
                          <button
                            onClick={() => onInvestigate(alert)}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-[11px] shadow-sm shadow-blue-500/20 transition-all cursor-pointer"
                            title="Diagnosticar causa con Copilot IA sin ocultar funcionalidades"
                          >
                            <Sparkles className="w-3 h-3" />
                            <span>Investigar</span>
                          </button>

                          {/* Mitigar Active Response */}
                          {!isContained && (
                            <button
                              onClick={() => canMitigate && onOpenMitigation(alert)}
                              disabled={!canMitigate}
                              className={`flex items-center gap-1 px-2 py-1 rounded-lg border font-medium text-[11px] transition-all ${
                                canMitigate
                                  ? 'bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white border-rose-500/30 cursor-pointer'
                                  : 'bg-slate-800/40 text-slate-600 border-slate-800 cursor-not-allowed'
                              }`}
                              title={
                                canMitigate
                                  ? 'Ejecutar Wazuh Active Response (Human-in-the-Loop)'
                                  : `Requiere rol ADMIN_SOC o ANALISTA_L2 (Tu rol: ${userRole})`
                              }
                            >
                              <ShieldBan className="w-3 h-3" />
                              <span>Mitigar</span>
                            </button>
                          )}

                          {/* Feedback TP / FP */}
                          {canEditStatus && (
                            <div className="flex items-center border-l border-slate-700/50 pl-1 ml-0.5">
                              <button
                                onClick={() => onFeedback(alert.alert_id, 'VERDADERO_POSITIVO')}
                                className="p-1 hover:text-emerald-400 text-slate-400 transition-colors cursor-pointer"
                                title="Confirmar Verdadero Positivo (TP) -> Reentrenar ML"
                              >
                                <CheckCircle className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => onFeedback(alert.alert_id, 'FALSO_POSITIVO')}
                                className="p-1 hover:text-amber-400 text-slate-400 transition-colors cursor-pointer"
                                title="Marcar Falso Positivo (FP) -> Reentrenar ML"
                              >
                                <XCircle className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          )}

                          {/* Eliminar Alerta (Solo ADMIN_SOC) */}
                          {isAdmin && (
                            <button
                              onClick={() => onDeleteAlert(alert.alert_id)}
                              className="p-1 hover:text-rose-400 text-slate-500 transition-colors cursor-pointer"
                              title="Eliminar alerta de PostgreSQL (Solo ADMIN_SOC)"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal de Inspección Forense (JSONB + Threat Intel en Vivo) */}
      {inspectAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[88vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-blue-400" />
                  <span>Evidencia Forense PostgreSQL JSONB — {inspectAlert.alert_id}</span>
                </h3>
                <p className="text-[11px] text-slate-400">{inspectAlert.title}</p>
              </div>
              <button
                onClick={() => setInspectAlert(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-4 text-xs">
              {/* Threat Intel Live Box */}
              <div className="p-3.5 rounded-xl bg-slate-950/90 border border-indigo-500/30 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-indigo-300 flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5" />
                    Threat Intelligence en Tiempo Real ({inspectAlert.raw_event?.source_ip})
                  </span>
                  {loadingTi && <span className="text-slate-400 text-[11px]">Consultando reputación...</span>}
                </div>
                {inspectThreatIntel ? (
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px]">
                    <div>
                      <span className="text-slate-500 block">País / Ciudad</span>
                      <span className="text-white font-semibold">
                        {inspectThreatIntel.country} ({inspectThreatIntel.city || 'N/A'})
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">ISP / ASN</span>
                      <span className="text-white font-semibold truncate block">{inspectThreatIntel.isp}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Abuse Score</span>
                      <span className="text-rose-400 font-mono font-bold">{inspectThreatIntel.abuse_score}%</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Fuente</span>
                      <span className="text-emerald-400 font-mono">{inspectThreatIntel.source}</span>
                    </div>
                  </div>
                ) : (
                  !loadingTi && <p className="text-slate-500 text-[11px]">Sin datos externos adicionales para esta IP.</p>
                )}
              </div>

              {/* ML Score & MITRE */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 font-semibold block mb-1">Evaluación ML (modelo_soc.pkl):</span>
                  <pre className="text-[11px] font-mono text-amber-300 overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify(inspectAlert.ml_score, null, 2)}
                  </pre>
                </div>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 font-semibold block mb-1">Estado Mitigación & Escenario:</span>
                  <div className="space-y-1 text-[11px]">
                    <div>
                      <span className="text-slate-500">Escenario: </span>
                      <span className="font-mono text-amber-300 font-bold">
                        {getScenarioInfo(inspectAlert).label}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Estado Actual: </span>
                      <span className="font-mono text-white font-bold">{inspectAlert.status}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Mitigación: </span>
                      <span className="text-emerald-400">{inspectAlert.mitigation_status}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Raw Event JSONB */}
              <div>
                <span className="text-slate-400 font-semibold block mb-1">
                  Payload Canónico / Crudo en PostgreSQL (<code className="text-blue-400">raw_event JSONB</code>):
                </span>
                <pre className="p-3 rounded-xl bg-black/80 border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(inspectAlert.raw_event, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-3.5 bg-slate-950 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setInspectAlert(null)}
                className="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold cursor-pointer"
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

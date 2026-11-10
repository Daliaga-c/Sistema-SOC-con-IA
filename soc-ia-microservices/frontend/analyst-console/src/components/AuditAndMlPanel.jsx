import React, { useState, useEffect } from 'react';
import {
  Brain,
  FileText,
  RefreshCw,
  Play,
  Download,
  CheckCircle2,
  XCircle,
  ShieldCheck
} from 'lucide-react';
import {
  fetchActiveLearningData,
  triggerManualRetrain,
  fetchAuditLogs
} from '../services/api';

export default function AuditAndMlPanel({ mode = 'ml', currentUser, onNotify, onOpenPredictor }) {
  const [alState, setAlState] = useState(null);
  const [goldenRecords, setGoldenRecords] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isRetraining, setIsRetraining] = useState(false);
  const [actionFilter, setActionFilter] = useState('TODAS');

  const canRetrain = currentUser?.role === 'ADMIN_SOC' || currentUser?.role === 'ANALISTA_L2';

  const loadData = async () => {
    setLoading(true);
    try {
      if (mode === 'ml') {
        const res = await fetchActiveLearningData();
        setAlState(res.active_learning_state || {});
        setGoldenRecords(res.golden_dataset?.records || []);
      } else {
        const res = await fetchAuditLogs(200);
        setAuditLogs(res.audit_logs || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [mode]);

  const handleManualRetrain = async () => {
    setIsRetraining(true);
    try {
      const sample = goldenRecords[0] || {
        alert_id: 'MANUAL-CALIBRATION',
        label: 'VERDADERO_POSITIVO',
        user: 'root',
        source_ip: '185.220.101.5',
        original_risk_score: 88.0
      };
      const res = await triggerManualRetrain(sample);
      if (onNotify) {
        onNotify(
          `🧠 Modelo recalibrado con éxito. Nuevo umbral dinámico: ${res.new_threshold_soc_model || 50}%`
        );
      }
      await loadData();
    } catch (err) {
      if (onNotify) onNotify(`⚠️ Error al reentrenar: ${err.message}`);
    } finally {
      setIsRetraining(false);
    }
  };

  const handleExportAuditCsv = () => {
    if (auditLogs.length === 0) return;
    const headers = ['id', 'created_at', 'alert_id', 'analyst_name', 'action', 'target', 'approved_by_human'];
    const rows = auditLogs.map((r) => [
      r.id,
      r.created_at || '',
      r.alert_id,
      `"${(r.analyst_name || '').replace(/"/g, '""')}"`,
      r.action,
      `"${(r.target || '').replace(/"/g, '""')}"`,
      r.approved_by_human
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.setAttribute('download', `soc_ia_audit_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  if (mode === 'ml') {
    return (
      <div className="space-y-6">
        {/* ML Engine Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800">
            <span className="text-xs text-slate-400 block">Clasificador Principal en Producción</span>
            <span className="text-base font-bold text-white block mt-1">
              modelo_soc.pkl (RandomForest 41-Feats)
            </span>
            <span className="text-[11px] text-emerald-400 font-mono">
              Esquema NSL-KDD calibrado para Wazuh SIEM
            </span>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800">
            <span className="text-xs text-slate-400 block">Umbral Dinámico (Active Learning)</span>
            <span className="text-2xl font-extrabold text-amber-400 font-mono block mt-1">
              {alState?.threshold_soc_model ?? 50.0}%
            </span>
            <span className="text-[11px] text-slate-500">
              TP acumulados: {alState?.tp_count ?? 0} | FP acumulados: {alState?.fp_count ?? 0}
            </span>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between gap-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-300 font-semibold">Acciones de Modelo ML:</span>
              <span className="text-[11px] font-mono text-blue-400">
                {goldenRecords.length} muestras en PostgreSQL
              </span>
            </div>
            <div className="flex gap-2">
              <button
                onClick={onOpenPredictor}
                className="flex-1 py-2 px-3 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Brain className="w-3.5 h-3.5" />
                <span>Abrir Predictor</span>
              </button>
              <button
                onClick={handleManualRetrain}
                disabled={isRetraining || !canRetrain}
                className="flex-1 py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 text-xs font-bold flex items-center justify-center gap-1.5 border border-slate-700 cursor-pointer"
              >
                <Play className={`w-3.5 h-3.5 ${isRetraining ? 'animate-spin' : ''}`} />
                <span>{isRetraining ? 'Reentrenando...' : 'Recalibrar ML'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Golden Dataset Table */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Brain className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-white">
                Golden Dataset de Retroalimentación (<code className="text-amber-400">ml_feedback_history</code> en PostgreSQL)
              </h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-semibold">
                {goldenRecords.length}
              </span>
            </div>
            <button
              onClick={loadData}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-semibold cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Actualizar</span>
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/50 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">ID / Fecha</th>
                  <th className="py-3 px-4">ID Alerta</th>
                  <th className="py-3 px-4">Clasificación Analista</th>
                  <th className="py-3 px-4">Usuario / IP</th>
                  <th className="py-3 px-4">Score Original</th>
                  <th className="py-3 px-4">Analista</th>
                  <th className="py-3 px-4">Estado Reentrenamiento</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {goldenRecords.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="py-8 text-center text-slate-400">
                      Aún no se han marcado alertas como TP o FP. Clasifica cualquier alerta en la pestaña de Incidentes para alimentar el Golden Dataset en PostgreSQL.
                    </td>
                  </tr>
                ) : (
                  goldenRecords.map((rec) => (
                    <tr key={rec.id} className="hover:bg-slate-800/30">
                      <td className="py-3 px-4">
                        <div className="font-mono text-slate-300">#{rec.id}</div>
                        <div className="text-[10px] text-slate-500">
                          {rec.created_at ? new Date(rec.created_at).toLocaleString() : ''}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-white">{rec.alert_id}</td>
                      <td className="py-3 px-4">
                        {rec.label === 'VERDADERO_POSITIVO' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px] font-bold">
                            <CheckCircle2 className="w-3 h-3" /> VERDADERO_POSITIVO
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[11px] font-bold">
                            <XCircle className="w-3 h-3" /> FALSO_POSITIVO
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {rec.user} @ {rec.source_ip}
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-slate-200">
                        {rec.original_risk_score}%
                      </td>
                      <td className="py-3 px-4 text-slate-300">{rec.analyst_name}</td>
                      <td className="py-3 px-4">
                        {rec.used_in_retraining ? (
                          <span className="text-emerald-400 font-semibold">✓ Aplicado al Modelo</span>
                        ) : (
                          <span className="text-slate-400">En Cola</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  }

  // mode === 'audit'
  const uniqueActions = ['TODAS', ...Array.from(new Set(auditLogs.map((a) => a.action)))];
  const filteredAudits = auditLogs.filter(
    (a) => actionFilter === 'TODAS' || a.action === actionFilter
  );

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
      <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-bold text-white">
            Bitácora Forense Inmutable (<code className="text-emerald-400">audit_logs</code> en PostgreSQL)
          </h3>
          <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-semibold">
            {filteredAudits.length}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-xl px-2.5 py-1.5 text-xs text-slate-200"
          >
            {uniqueActions.map((act) => (
              <option key={act} value={act}>
                {act === 'TODAS' ? 'Todas las acciones' : act}
              </option>
            ))}
          </select>

          <button
            onClick={handleExportAuditCsv}
            disabled={filteredAudits.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-semibold border border-slate-700 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span>Exportar CSV</span>
          </button>

          <button
            onClick={loadData}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 font-semibold cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Actualizar</span>
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/50 text-slate-400 uppercase text-[10px] border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">ID / Fecha UTC</th>
              <th className="py-3 px-4">Acción Auditada</th>
              <th className="py-3 px-4">Operador Responsable</th>
              <th className="py-3 px-4">Referencia / Objetivo</th>
              <th className="py-3 px-4">Detalles Forenses (JSONB)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {filteredAudits.length === 0 ? (
              <tr>
                <td colSpan="5" className="py-8 text-center text-slate-400">
                  Sin registros de auditoría para el filtro seleccionado.
                </td>
              </tr>
            ) : (
              filteredAudits.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/30">
                  <td className="py-3 px-4">
                    <div className="font-mono text-slate-300">#{log.id}</div>
                    <div className="text-[10px] text-slate-500">
                      {log.created_at ? new Date(log.created_at).toLocaleString() : ''}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-blue-300 border border-slate-700">
                      {log.action}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-semibold text-white">{log.analyst_name}</td>
                  <td className="py-3 px-4">
                    <div className="font-mono text-slate-200">{log.target}</div>
                    <div className="text-[10px] text-slate-500">{log.alert_id}</div>
                  </td>
                  <td className="py-3 px-4">
                    <pre className="text-[10px] font-mono text-slate-400 max-w-md overflow-x-auto whitespace-pre-wrap">
                      {JSON.stringify(log.details || {})}
                    </pre>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

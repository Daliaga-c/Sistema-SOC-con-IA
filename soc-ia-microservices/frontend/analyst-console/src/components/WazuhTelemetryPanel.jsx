import React, { useState, useEffect } from 'react';
import { Radio, RefreshCw, Flame, CheckCircle2, Server, Database, AlertCircle } from 'lucide-react';
import {
  fetchWazuhBuffer,
  fetchWazuhStatus,
  syncWazuhAlerts,
  escalateWazuhBufferEvent
} from '../services/api';

export default function WazuhTelemetryPanel({ currentUser, onNotify, onAlertsUpdated }) {
  const [bufferEvents, setBufferEvents] = useState([]);
  const [totalBuffered, setTotalBuffered] = useState(0);
  const [wazuhStatus, setWazuhStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncLimit, setSyncLimit] = useState(25);
  const [minLevel, setMinLevel] = useState(3);
  const [error, setError] = useState('');

  const canModify = currentUser?.role !== 'AUDITOR';

  const loadData = async () => {
    setLoading(true);
    setError('');
    try {
      const [bufRes, statusRes] = await Promise.all([
        fetchWazuhBuffer(100),
        fetchWazuhStatus()
      ]);
      setBufferEvents(bufRes.events || []);
      setTotalBuffered(bufRes.total || 0);
      setWazuhStatus(statusRes);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSyncNow = async () => {
    setIsSyncing(true);
    setError('');
    try {
      const res = await syncWazuhAlerts(syncLimit, minLevel);
      if (onNotify) {
        onNotify(
          `📡 Sincronizados ${res.fetched_and_evaluated} eventos reales de Wazuh Indexer (${res.escalated_to_alerts} escalados a alertas)`
        );
      }
      await loadData();
      if (onAlertsUpdated) onAlertsUpdated();
    } catch (err) {
      setError(err.message);
    } finally {
      setIsSyncing(false);
    }
  };

  const handleEscalateEvent = async (eventId) => {
    try {
      const res = await escalateWazuhBufferEvent(eventId);
      if (onNotify) {
        onNotify(`🚨 Evento ${eventId} escalado a alerta activa (${res.alert?.alert_id})`);
      }
      await loadData();
      if (onAlertsUpdated) onAlertsUpdated();
    } catch (err) {
      setError(err.message);
    }
  };

  const mgrOk = wazuhStatus?.wazuh_manager?.connected;
  const idxOk = wazuhStatus?.wazuh_indexer?.connected;
  const idxDocs = wazuhStatus?.wazuh_indexer?.total_indexed_alerts ?? 0;

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Wazuh Connection Status & Live Sync Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 block">Wazuh Manager API (:55000)</span>
            <span className={`text-sm font-bold ${mgrOk ? 'text-emerald-400' : 'text-rose-400'}`}>
              {mgrOk ? '● CONECTADO (JWT Activo)' : '● DESCONECTADO'}
            </span>
            <span className="text-[11px] text-slate-500 block font-mono mt-0.5">
              {wazuhStatus?.wazuh_manager?.host || 'host.docker.internal:55000'}
            </span>
          </div>
          <Server className="w-6 h-6 text-blue-400" />
        </div>

        <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 block">Wazuh Indexer OpenSearch (:9200)</span>
            <span className={`text-sm font-bold ${idxOk ? 'text-emerald-400' : 'text-rose-400'}`}>
              {idxOk ? `● ONLINE (${idxDocs} alertas en SIEM)` : '● DESCONECTADO'}
            </span>
            <span className="text-[11px] text-slate-500 block font-mono mt-0.5">
              Índice: wazuh-alerts-4.x-*
            </span>
          </div>
          <Database className="w-6 h-6 text-purple-400" />
        </div>

        <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between gap-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-300 font-semibold">Sincronizar con Wazuh Indexer:</span>
            <div className="flex items-center gap-2">
              <label className="text-[11px] text-slate-400">
                Límite:
                <input
                  type="number"
                  min={5}
                  max={100}
                  value={syncLimit}
                  onChange={(e) => setSyncLimit(Number(e.target.value) || 20)}
                  className="ml-1 w-14 bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-white font-mono"
                />
              </label>
              <label className="text-[11px] text-slate-400">
                Nivel ≥
                <input
                  type="number"
                  min={1}
                  max={15}
                  value={minLevel}
                  onChange={(e) => setMinLevel(Number(e.target.value) || 3)}
                  className="ml-1 w-12 bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-white font-mono"
                />
              </label>
            </div>
          </div>

          <button
            onClick={handleSyncNow}
            disabled={isSyncing || !canModify}
            className="w-full py-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 disabled:opacity-40 text-white text-xs font-bold flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
            <span>
              {isSyncing
                ? 'Extrayendo de Wazuh Indexer y evaluando con modelo_soc.pkl...'
                : 'Sincronizar Alertas Reales de Wazuh SIEM'}
            </span>
          </button>
        </div>
      </div>

      {/* Buffered Events Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-bold text-white">
              Buffer Persistente de Eventos Wazuh (<code className="text-purple-400">wazuh_raw_events</code> en PostgreSQL)
            </h3>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-semibold">
              {totalBuffered}
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
                <th className="py-3 px-4">ID Evento / Fecha</th>
                <th className="py-3 px-4">Regla Wazuh</th>
                <th className="py-3 px-4">Usuario / Agente</th>
                <th className="py-3 px-4">IP Origen</th>
                <th className="py-3 px-4">Score modelo_soc.pkl</th>
                <th className="py-3 px-4">Estado Escalado</th>
                <th className="py-3 px-4 text-right">Acción</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {bufferEvents.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-8 text-center text-slate-400">
                    El buffer <code className="text-purple-400">wazuh_raw_events</code> está vacío. Haz clic en{' '}
                    <strong>"Sincronizar Alertas Reales de Wazuh SIEM"</strong> arriba para importar desde OpenSearch (:9200).
                  </td>
                </tr>
              ) : (
                bufferEvents.map((ev) => {
                  const risk = ev.ml_evaluation?.risk_score ?? 0;
                  const ruleDesc =
                    ev.raw_payload?.metadata?.wazuh?.rule_description || ev.source_system;
                  return (
                    <tr key={ev.event_id} className="hover:bg-slate-800/30">
                      <td className="py-3 px-4">
                        <div className="font-mono font-bold text-slate-200">{ev.event_id}</div>
                        <div className="text-[10px] text-slate-500">
                          {ev.received_at ? new Date(ev.received_at).toLocaleString() : ''}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-semibold text-white">
                          Rule {ev.rule_id} (Nivel {ev.rule_level})
                        </div>
                        <div className="text-[11px] text-slate-400 max-w-xs truncate" title={ruleDesc}>
                          {ruleDesc}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-semibold text-blue-300">{ev.user}</td>
                      <td className="py-3 px-4 font-mono text-slate-300">{ev.source_ip}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`font-mono font-bold ${
                            risk >= 70 ? 'text-rose-400' : risk >= 40 ? 'text-amber-400' : 'text-emerald-400'
                          }`}
                        >
                          {risk}%
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {ev.escalated_to_alert ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px]">
                            <CheckCircle2 className="w-3 h-3" /> En Alertas Activas
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-400">Solo en Buffer</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        {!ev.escalated_to_alert && canModify && (
                          <button
                            onClick={() => handleEscalateEvent(ev.event_id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white border border-rose-500/30 text-[11px] font-semibold transition-colors cursor-pointer"
                          >
                            <Flame className="w-3 h-3" />
                            <span>Escalar a Alerta</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

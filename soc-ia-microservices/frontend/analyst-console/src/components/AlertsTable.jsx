import React, { useState } from 'react';
import { Search, Bot, ShieldBan, Sparkles, Filter, CheckCircle, XCircle } from 'lucide-react';

export default function AlertsTable({
  alerts = [],
  onInvestigate,
  onOpenMitigation,
  onFeedback,
  loading = false
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('TODAS');

  const filtered = alerts.filter(alert => {
    const user = alert.raw_event?.user || '';
    const ip = alert.raw_event?.source_ip || '';
    const id = alert.alert_id || '';
    const matchesSearch = user.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          id.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = filterSeverity === 'TODAS' || alert.severity === filterSeverity;
    return matchesSearch && matchesSeverity;
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

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl shadow-xl shadow-black/30">
      {/* Table Header / Filters Bar */}
      <div className="p-4 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-bold text-white tracking-wide">Alertas de Autenticación Activas</h2>
          <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
            {filtered.length}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Buscar por IP, usuario o ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors w-52 sm:w-64"
            />
          </div>

          {/* Severity Filter Dropdown */}
          <div className="flex items-center gap-1 bg-slate-950/60 border border-slate-800 rounded-xl px-2 py-1 text-xs">
            <Filter className="w-3 h-3 text-slate-400" />
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-transparent text-slate-300 text-xs focus:outline-none cursor-pointer"
            >
              <option value="TODAS">Todas las severidades</option>
              <option value="CRÍTICA">Crítica</option>
              <option value="ALTA">Alta</option>
              <option value="MEDIA">Media</option>
              <option value="BAJA">Baja</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table Body */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/40 text-slate-400 font-semibold border-b border-slate-800/60 uppercase tracking-wider text-[10px]">
            <tr>
              <th className="py-3 px-4">ID Alerta</th>
              <th className="py-3 px-4">Origen</th>
              <th className="py-3 px-4">Usuario</th>
              <th className="py-3 px-4">IP Origen</th>
              <th className="py-3 px-4">Severidad</th>
              <th className="py-3 px-4">Score Riesgo ML</th>
              <th className="py-3 px-4">Mitigación / Estado</th>
              <th className="py-3 px-4 text-right">Acciones</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {loading ? (
              <tr>
                <td colSpan="8" className="py-8 text-center text-slate-500">
                  Cargando telemetría del SOC...
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan="8" className="py-8 text-center text-slate-500">
                  No se encontraron alertas que coincidan con los filtros.
                </td>
              </tr>
            ) : (
              filtered.map((alert) => {
                const risk = alert.ml_score?.risk_score || 0;
                const isContained = alert.status === 'CONTENIDA' || alert.mitigation_status?.includes('EJECUTADA');

                return (
                  <tr key={alert.alert_id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="py-3 px-4 font-mono font-medium text-slate-300">
                      {alert.alert_id}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      <span className="px-2 py-0.5 rounded-md bg-slate-800/60 border border-slate-700/40 text-[11px]">
                        {alert.raw_event?.source_system || 'Wazuh SIEM'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-semibold text-white">
                      {alert.raw_event?.user || 'N/A'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {alert.raw_event?.source_ip || 'N/A'}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold border ${getSeverityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              risk >= 80 ? 'bg-rose-500' : risk >= 60 ? 'bg-orange-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${risk}%` }}
                          />
                        </div>
                        <span className="font-mono font-bold text-slate-200">{risk}%</span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      {isContained ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                          <CheckCircle className="w-3 h-3" /> Bloqueada
                        </span>
                      ) : (
                        <span className="text-[11px] text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full border border-amber-500/20">
                          Pendiente
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {/* Botón Investigar con IA */}
                        <button
                          onClick={() => onInvestigate(alert)}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-[11px] shadow-sm shadow-blue-500/20 transition-all hover:scale-[1.02]"
                          title="Analizar con Copilot RAG"
                        >
                          <Sparkles className="w-3 h-3" />
                          <span>Investigar</span>
                        </button>

                        {/* Botón Mitigar Active Response */}
                        {!isContained && (
                          <button
                            onClick={() => onOpenMitigation(alert)}
                            className="flex items-center gap-1 px-2 py-1 rounded-lg bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white border border-rose-500/30 font-medium text-[11px] transition-all"
                            title="Bloquear IP en Firewall"
                          >
                            <ShieldBan className="w-3 h-3" />
                            <span>Bloquear</span>
                          </button>
                        )}

                        {/* Feedback TP / FP (Active Learning) */}
                        <div className="flex items-center border-l border-slate-700/50 pl-1.5 ml-1">
                          <button
                            onClick={() => onFeedback(alert.alert_id, 'VERDADERO_POSITIVO')}
                            className="p-1 hover:text-emerald-400 text-slate-500 transition-colors"
                            title="Confirmar Verdadero Positivo (TP)"
                          >
                            <CheckCircle className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => onFeedback(alert.alert_id, 'FALSO_POSITIVO')}
                            className="p-1 hover:text-amber-400 text-slate-500 transition-colors"
                            title="Marcar Falso Positivo (FP)"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                          </button>
                        </div>
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
  );
}

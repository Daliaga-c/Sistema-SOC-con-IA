import React, { useState } from 'react';
import { Search, Bot, Ban, CheckCircle2, ChevronRight, Activity } from 'lucide-react';

export default function AlertsTable({ alerts, onSelectAlert, selectedAlert, onMitigate }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const filtered = alerts.filter(a => {
    const matchesSearch =
      a.title?.toLowerCase().includes(search.toLowerCase()) ||
      a.raw_event?.user?.toLowerCase().includes(search.toLowerCase()) ||
      a.raw_event?.source_ip?.includes(search) ||
      a.alert_id?.toLowerCase().includes(search.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || a.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRÍTICA':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
      case 'ALTA':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'MEDIA':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  return (
    <div className="rounded-xl border border-white/10 bg-[#121826]/90 backdrop-blur-md overflow-hidden flex flex-col">
      {/* Barra de Filtros */}
      <div className="p-4 border-b border-white/10 flex flex-wrap items-center justify-between gap-3 bg-[#0d131f]/50">
        <div className="flex items-center gap-2 flex-1 max-w-md bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-xs">
          <Search className="w-3.5 h-3.5 text-slate-400" />
          <input
            type="text"
            placeholder="Buscar por IP, usuario, ID o título..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent border-none outline-none text-slate-200 placeholder-slate-500 w-full"
          />
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Severidad:</span>
          {['ALL', 'CRÍTICA', 'ALTA', 'MEDIA'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-md transition-all font-medium ${
                severityFilter === sev
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-white/5 text-slate-400 hover:text-white'
              }`}
            >
              {sev === 'ALL' ? 'Todas' : sev}
            </button>
          ))}
        </div>
      </div>

      {/* Tabla */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0b0f19] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-white/10">
            <tr>
              <th className="py-3 px-4">ID / Incidente</th>
              <th className="py-3 px-4">Severidad</th>
              <th className="py-3 px-4">Origen & Usuario</th>
              <th className="py-3 px-4">IP Origen</th>
              <th className="py-3 px-4">Riesgo ML</th>
              <th className="py-3 px-4">MITRE ATT&CK</th>
              <th className="py-3 px-4 text-right">Acciones</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="7" className="py-8 text-center text-slate-500 italic">
                  No se encontraron incidentes que coincidan con los filtros.
                </td>
              </tr>
            ) : (
              filtered.map((alert) => {
                const isSelected = selectedAlert?.alert_id === alert.alert_id;
                const risk = alert.ml_score?.risk_score || 0;
                const isMitigated = alert.mitigation_status === 'BLOQUEADO';

                return (
                  <tr
                    key={alert.alert_id}
                    className={`transition-colors cursor-pointer ${
                      isSelected ? 'bg-blue-600/10' : 'hover:bg-white/[0.03]'
                    }`}
                    onClick={() => onSelectAlert(alert)}
                  >
                    <td className="py-3.5 px-4 font-mono font-medium text-slate-200">
                      <div className="flex items-center gap-2">
                        <span className="text-blue-400 font-semibold">{alert.alert_id}</span>
                        {isSelected && <ChevronRight className="w-3.5 h-3.5 text-blue-400" />}
                      </div>
                      <div className="text-[11px] text-slate-400 font-sans truncate max-w-xs">
                        {alert.title}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-300">
                        {alert.raw_event?.user || 'N/A'}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        {alert.raw_event?.source_system || 'Web'}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 font-mono text-slate-300">
                      {alert.raw_event?.source_ip || 'N/A'}
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full ${
                              risk >= 80 ? 'bg-rose-500' : risk >= 60 ? 'bg-amber-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${risk}%` }}
                          />
                        </div>
                        <span className="font-mono text-slate-300 font-bold">{risk}</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1">
                        {(alert.mitre_attack || ['T1110']).map((t, idx) => (
                          <span
                            key={idx}
                            className="bg-white/5 border border-white/10 px-1.5 py-0.5 rounded text-[10px] text-slate-400 font-mono"
                          >
                            {t.split(' - ')[0]}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3.5 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => onSelectAlert(alert)}
                          className="p-1.5 rounded bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 transition-all"
                          title="Investigar con Copilot IA"
                        >
                          <Bot className="w-4 h-4" />
                        </button>

                        <button
                          onClick={() => onMitigate(alert)}
                          disabled={isMitigated}
                          className={`p-1.5 rounded transition-all border ${
                            isMitigated
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 cursor-not-allowed'
                              : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border-rose-500/20'
                          }`}
                          title={isMitigated ? 'IP Ya Bloqueada' : 'Bloquear IP en Wazuh (HITL)'}
                        >
                          {isMitigated ? <CheckCircle2 className="w-4 h-4" /> : <Ban className="w-4 h-4" />}
                        </button>
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


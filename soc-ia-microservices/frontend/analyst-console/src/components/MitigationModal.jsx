import React, { useState } from 'react';
import { ShieldAlert, AlertOctagon, Check, X, Terminal } from 'lucide-react';

export default function MitigationModal({
  isOpen,
  onClose,
  alert,
  onConfirm,
  isExecuting
}) {
  const [analystName, setAnalystName] = useState('Diego Aliaga (Analista N1)');
  const [confirmedCheck, setConfirmedCheck] = useState(false);

  if (!isOpen || !alert) return null;

  const targetIp = alert.raw_event?.source_ip || 'N/A';
  const targetUser = alert.raw_event?.user || 'N/A';
  const mitreTactic = alert.mitre_attack?.[0] || 'T1110 - Brute Force';

  const handleExecute = () => {
    if (!confirmedCheck) return;
    onConfirm({
      alertId: alert.alert_id,
      action: 'BLOCK_IP',
      target: targetIp,
      analystName: analystName
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-md w-full shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 bg-rose-950/40 border-b border-rose-900/30 flex items-center justify-between">
          <div className="flex items-center gap-2.5 text-rose-400">
            <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Aprobación de Mitigación (HITL)</h3>
              <p className="text-[11px] text-rose-300/80">Control de Gobernanza: Human-in-the-Loop</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 text-xs">
          <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">ID de Alerta:</span>
              <span className="font-mono font-bold text-slate-200">{alert.alert_id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">IP a Bloquear (Target):</span>
              <span className="font-mono font-bold text-rose-400">{targetIp}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Usuario Afectado:</span>
              <span className="font-semibold text-slate-200">{targetUser}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Técnica MITRE:</span>
              <span className="text-purple-300 font-medium">{mitreTactic}</span>
            </div>
          </div>

          {/* Command Preview */}
          <div>
            <span className="text-[11px] font-semibold text-slate-400 block mb-1.5 flex items-center gap-1">
              <Terminal className="w-3.5 h-3.5 text-blue-400" />
              Comando a Despachar en Wazuh Active Response:
            </span>
            <div className="p-2.5 bg-black/70 rounded-lg font-mono text-[11px] text-emerald-400 border border-emerald-500/20">
              PUT /active-response {"{"} "command": "firewall-drop0", "arguments": ["-", "{targetIp}"] {"}"}
            </div>
          </div>

          {/* Operator Signature */}
          <div className="space-y-1.5">
            <label className="text-slate-400 font-medium block">Firma y Responsable del Bloqueo:</label>
            <input
              type="text"
              value={analystName}
              onChange={(e) => setAnalystName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-1.5 text-xs text-white focus:outline-none focus:border-rose-500"
            />
          </div>

          {/* Confirmation Checkbox */}
          <label className="flex items-start gap-2.5 p-2.5 bg-rose-500/5 border border-rose-500/20 rounded-xl cursor-pointer">
            <input
              type="checkbox"
              checked={confirmedCheck}
              onChange={(e) => setConfirmedCheck(e.target.checked)}
              className="mt-0.5 rounded border-slate-700 text-rose-600 focus:ring-0"
            />
            <span className="text-[11px] text-slate-300 leading-tight">
              Confirmo que he revisado la telemetría y autorizo el bloqueo temporal de la IP en el firewall de los agentes.
            </span>
          </label>
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-slate-950/60 border-t border-slate-800 flex items-center justify-end gap-2">
          <button
            onClick={onClose}
            disabled={isExecuting}
            className="px-3 py-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors text-xs font-semibold"
          >
            Cancelar
          </button>
          <button
            onClick={handleExecute}
            disabled={!confirmedCheck || isExecuting}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white font-bold text-xs transition-colors shadow-lg shadow-rose-600/25"
          >
            {isExecuting ? (
              <span>Despachando a Wazuh...</span>
            ) : (
              <>
                <Check className="w-3.5 h-3.5" />
                <span>Ejecutar Active Response</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

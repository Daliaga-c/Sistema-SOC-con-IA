import React, { useState, useEffect } from 'react';
import { ShieldAlert, Check, X, Terminal } from 'lucide-react';

export default function MitigationModal({
  isOpen,
  onClose,
  alert,
  currentUser,
  onConfirm,
  isExecuting
}) {
  const [action, setAction] = useState('BLOCK_IP');
  const [confirmedCheck, setConfirmedCheck] = useState(false);

  useEffect(() => {
    setConfirmedCheck(false);
    setAction('BLOCK_IP');
  }, [alert, isOpen]);

  if (!isOpen || !alert) return null;

  const targetIp = alert.raw_event?.source_ip || '127.0.0.1';
  const targetUser = alert.raw_event?.user || 'unknown';
  const operatorSignature = `${currentUser?.name || 'Operador'} (${currentUser?.role || 'ANALISTA_L2'})`;

  const targetValue = action === 'DISABLE_ACCOUNT' ? targetUser : targetIp;
  const wazuhCommand =
    action === 'BLOCK_IP'
      ? 'firewall-drop0'
      : action === 'ISOLATE_HOST'
      ? 'host-deny'
      : 'disable-account';

  const handleExecute = () => {
    if (!confirmedCheck) return;
    onConfirm({
      alertId: alert.alert_id,
      action,
      target: targetValue,
      analystName: operatorSignature
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-md w-full shadow-2xl overflow-hidden">
        <div className="p-4 bg-rose-950/40 border-b border-rose-900/30 flex items-center justify-between">
          <div className="flex items-center gap-2.5 text-rose-400">
            <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Aprobación Active Response (HITL)</h3>
              <p className="text-[11px] text-rose-300/80">Gobernanza Human-in-the-Loop • Wazuh Manager :55000</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4 text-xs">
          <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-400">ID de Alerta:</span>
              <span className="font-mono font-bold text-slate-200">{alert.alert_id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">IP Origen:</span>
              <span className="font-mono font-bold text-rose-400">{targetIp}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Cuenta Afectada:</span>
              <span className="font-semibold text-slate-200">{targetUser}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Operador Autorizante:</span>
              <span className="text-emerald-400 font-semibold">{operatorSignature}</span>
            </div>
          </div>

          <div>
            <label className="text-slate-300 font-semibold block mb-1.5">
              Seleccionar Acción de Contención en Wazuh:
            </label>
            <select
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-rose-500"
            >
              <option value="BLOCK_IP">BLOCK_IP — Bloquear IP en Firewall (firewall-drop0)</option>
              <option value="ISOLATE_HOST">ISOLATE_HOST — Denegar Host en Red (host-deny)</option>
              <option value="DISABLE_ACCOUNT">DISABLE_ACCOUNT — Suspender Cuenta ({targetUser})</option>
            </select>
          </div>

          <div>
            <span className="text-[11px] font-semibold text-slate-400 block mb-1.5 flex items-center gap-1">
              <Terminal className="w-3.5 h-3.5 text-blue-400" />
              Payload REST hacia Wazuh Manager (:55000):
            </span>
            <div className="p-2.5 bg-black/80 rounded-lg font-mono text-[11px] text-emerald-400 border border-emerald-500/20">
              PUT /active-response {"{"} "command": "{wazuhCommand}", "arguments": ["-", "{targetValue}"] {"}"}
            </div>
          </div>

          <label className="flex items-start gap-2.5 p-2.5 bg-rose-500/5 border border-rose-500/20 rounded-xl cursor-pointer">
            <input
              type="checkbox"
              checked={confirmedCheck}
              onChange={(e) => setConfirmedCheck(e.target.checked)}
              className="mt-0.5 rounded border-slate-700 text-rose-600 focus:ring-0"
            />
            <span className="text-[11px] text-slate-300 leading-tight">
              Autorizo bajo mi firma ({operatorSignature}) la ejecución de este comando en Wazuh Active Response y su registro inmutable en <code className="text-rose-300">audit_logs</code> (PostgreSQL).
            </span>
          </label>
        </div>

        <div className="p-4 bg-slate-950/60 border-t border-slate-800 flex items-center justify-end gap-2">
          <button
            onClick={onClose}
            disabled={isExecuting}
            className="px-3 py-1.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition-colors text-xs font-semibold cursor-pointer"
          >
            Cancelar
          </button>
          <button
            onClick={handleExecute}
            disabled={!confirmedCheck || isExecuting}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 disabled:opacity-40 text-white font-bold text-xs transition-colors shadow-lg shadow-rose-600/25 cursor-pointer"
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

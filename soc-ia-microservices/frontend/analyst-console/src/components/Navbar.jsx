import React from 'react';
import { Shield, LogOut, Database, Cpu, Bot, Radio } from 'lucide-react';

const ROLE_BADGES = {
  ADMIN_SOC: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  ANALISTA_L2: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  ANALISTA_L1: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  AUDITOR: 'bg-amber-500/15 text-amber-300 border-amber-500/30'
};

export default function Navbar({ currentUser, onLogout, systemHealth }) {
  const initials = currentUser?.name
    ? currentUser.name
        .split(' ')
        .map((n) => n[0])
        .join('')
        .substring(0, 2)
        .toUpperCase()
    : 'OP';

  const pgOk = systemHealth?.postgres?.status === 'UP';
  const wazuhOk = systemHealth?.wazuh?.status === 'CONNECTED';
  const wazuhIndexed = systemHealth?.wazuh?.wazuh_indexer?.total_indexed_alerts ?? 0;
  const mlOk = systemHealth?.ml_engine?.status === 'UP';
  const copilotInfo = systemHealth?.copilot_ai || {};
  const copilotOnline = copilotInfo?.status === 'ONLINE' || copilotInfo?.gemini?.available || copilotInfo?.ollama?.available;
  const activeAiProvider = copilotInfo?.active_provider || (copilotInfo?.ollama?.available ? `Ollama (${copilotInfo?.ollama?.active_model})` : 'OFFLINE');

  return (
    <header className="border-b border-slate-800/80 bg-slate-900/75 backdrop-blur-xl sticky top-0 z-40 px-4 sm:px-6 py-3 flex items-center justify-between gap-4">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/25">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-tight text-white">SOC-IA Platform</h1>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              v3.0 Producción
            </span>
          </div>
          <p className="text-xs text-slate-400">
            PostgreSQL 15 • Wazuh SIEM Live • <code className="text-blue-400">modelo_soc.pkl</code> • Gemini & Ollama
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Live Telemetry Status Bar */}
        <div className="hidden xl:flex items-center gap-3 text-[11px] text-slate-300 bg-slate-950/70 px-3.5 py-1.5 rounded-xl border border-slate-800">
          <div className="flex items-center gap-1.5" title="Estado en vivo de PostgreSQL 15 (soc_incidents)">
            <span className={`w-2 h-2 rounded-full ${pgOk ? 'bg-emerald-400' : 'bg-rose-500 animate-ping'}`} />
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span>PostgreSQL 15</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5" title={`Wazuh SIEM Indexer (${wazuhIndexed} alertas indexadas)`}>
            <span className={`w-2 h-2 rounded-full ${wazuhOk ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
            <Radio className="w-3.5 h-3.5 text-slate-400" />
            <span>Wazuh SIEM ({wazuhIndexed})</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5" title="Motor Random Forest NSL-KDD (modelo_soc.pkl)">
            <span className={`w-2 h-2 rounded-full ${mlOk ? 'bg-cyan-400' : 'bg-rose-500'}`} />
            <Cpu className="w-3.5 h-3.5 text-slate-400" />
            <span>modelo_soc.pkl</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5" title={`Motor LLM activo: ${activeAiProvider}`}>
            <span className={`w-2 h-2 rounded-full ${copilotOnline ? 'bg-purple-400' : 'bg-rose-500'}`} />
            <Bot className="w-3.5 h-3.5 text-slate-400" />
            <span className="truncate max-w-[165px]">{activeAiProvider}</span>
          </div>
        </div>

        {/* Logged Operator Badge & Logout */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2.5 bg-slate-800/70 px-3 py-1.5 rounded-xl border border-slate-700/70 text-xs">
            <div className="w-7 h-7 rounded-lg bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold text-xs">
              {initials}
            </div>
            <div className="leading-tight">
              <div className="flex items-center gap-1.5">
                <span className="text-white font-semibold">{currentUser?.name}</span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                    ROLE_BADGES[currentUser?.role] || 'bg-slate-700 text-slate-300 border-slate-600'
                  }`}
                >
                  {currentUser?.role}
                </span>
              </div>
              <div className="text-[10px] text-slate-400 font-mono">{currentUser?.email}</div>
            </div>
          </div>

          <button
            onClick={onLogout}
            className="flex items-center gap-1.5 px-2.5 py-2 rounded-xl bg-slate-800/60 hover:bg-rose-500/15 text-slate-300 hover:text-rose-400 border border-slate-700/70 hover:border-rose-500/30 transition-all text-xs cursor-pointer"
            title="Cerrar Sesión (Vuelve a exigir Login)"
          >
            <LogOut className="w-4 h-4" />
            <span className="hidden sm:inline font-semibold">Salir</span>
          </button>
        </div>
      </div>
    </header>
  );
}

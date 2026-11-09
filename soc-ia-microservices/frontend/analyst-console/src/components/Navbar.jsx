import React from 'react';
import { Shield, Radio, Activity, Cpu, LogOut } from 'lucide-react';

export default function Navbar({ onRefresh, isRefreshing, currentUser, onLogout }) {
  const initials = currentUser?.name
    ? currentUser.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase()
    : 'DA';

  return (
    <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-xl sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/25">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-tight text-white">SOC-IA Platform</h1>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
              v2.0 React
            </span>
          </div>
          <p className="text-xs text-slate-400">Triaje de Autenticación & Correlación Wazuh SIEM + GenAI</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* System Status Indicators */}
        <div className="hidden md:flex items-center gap-3 text-xs text-slate-400 bg-slate-950/40 px-3 py-1.5 rounded-lg border border-slate-800">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Wazuh SIEM</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            <span>ML Anomaly</span>
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-purple-400"></span>
            <span>Copilot RAG</span>
          </div>
        </div>

        {/* User Badge & Logout */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2.5 bg-slate-800/60 px-3 py-1.5 rounded-xl border border-slate-700/60 text-xs">
            <div className="w-6 h-6 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-[11px]">
              {initials}
            </div>
            <div>
              <div className="text-white font-medium">{currentUser?.name || 'Diego Aliaga'}</div>
              <div className="text-[10px] text-slate-400">{currentUser?.role || 'Analista SOC N1'}</div>
            </div>
          </div>

          <button
            onClick={onLogout}
            className="p-2 rounded-xl bg-slate-800/40 hover:bg-rose-500/10 text-slate-400 hover:text-rose-400 border border-slate-700/60 hover:border-rose-500/30 transition-all text-xs"
            title="Cerrar Sesión"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}

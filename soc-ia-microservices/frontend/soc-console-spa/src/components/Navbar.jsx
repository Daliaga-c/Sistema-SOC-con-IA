import React, { useState, useEffect } from 'react';
import { Shield, Radio, RefreshCw, UserCheck } from 'lucide-react';

export default function Navbar({ onRefresh, isRefreshing, gatewayOnline }) {
  const [timeUtc, setTimeUtc] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeUtc(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="border-b border-white/10 bg-[#0f1523]/80 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight text-white">SOC-IA Platform</h1>
            <span className="text-[10px] font-mono uppercase bg-blue-500/20 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded-full">
              React 18 SPA
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Centro de Operaciones de Seguridad Inteligente &middot; Triaje con IA
          </p>
        </div>
      </div>

      <div className="flex items-center gap-6">
        {/* Reloj UTC */}
        <div className="hidden md:flex flex-col text-right font-mono text-xs text-slate-400">
          <span className="text-slate-200">{timeUtc}</span>
          <span className="text-[10px] text-slate-500">Horario Oficial de Auditoría</span>
        </div>

        {/* Estado Gateway */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs">
          <div className={`w-2.5 h-2.5 rounded-full ${gatewayOnline ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
          <span className="text-slate-300 font-medium">
            {gatewayOnline ? 'Gateway Activo' : 'Desconectado'}
          </span>
        </div>

        {/* Analista */}
        <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
          <UserCheck className="w-4 h-4 text-blue-400" />
          <span>Analista N1: <strong>Diego Aliaga</strong></span>
        </div>

        {/* Botón Refrescar */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 text-xs text-white transition-all disabled:opacity-50"
          title="Sincronizar alertas con el backend"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span>Sincronizar</span>
        </button>
      </div>
    </header>
  );
}


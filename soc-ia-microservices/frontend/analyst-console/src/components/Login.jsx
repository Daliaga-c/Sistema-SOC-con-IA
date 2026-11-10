import React, { useState } from 'react';
import { Shield, Mail, Lock, ShieldCheck, ArrowRight, AlertCircle, Database, Users } from 'lucide-react';
import { loginUser } from '../services/api';

const QUICK_ACCOUNTS = [
  {
    label: 'Administrador SOC (ADMIN_SOC)',
    email: 'admin.soc@empresa.com',
    pass: 'admin-soc-2025',
    badge: 'bg-purple-500/15 text-purple-300 border-purple-500/30'
  },
  {
    label: 'Analista Senior N2 (ANALISTA_L2)',
    email: 'analista.soc@empresa.com',
    pass: 'soc-ia-2025',
    badge: 'bg-blue-500/15 text-blue-300 border-blue-500/30'
  },
  {
    label: 'Analista Triaje N1 (ANALISTA_L1)',
    email: 'triaje.soc@empresa.com',
    pass: 'triaje-soc-2025',
    badge: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
  },
  {
    label: 'Auditor Forense (AUDITOR)',
    email: 'auditor.soc@empresa.com',
    pass: 'auditor-soc-2025',
    badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30'
  }
];

export default function Login({ onLoginSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email.trim() || !password.trim()) {
      setError('Ingresa tu correo institucional y contraseña.');
      return;
    }

    setIsLoading(true);
    try {
      const response = await loginUser(email.trim(), password);
      onLoginSuccess({
        ...response.user,
        token: response.token
      });
    } catch (err) {
      setError(err.message || 'Credenciales inválidas o servidor fuera de línea.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFillAccount = (acc) => {
    setEmail(acc.email);
    setPassword(acc.pass);
    setError('');
  };

  return (
    <div className="min-h-screen bg-[#090d16] flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-slate-900/90 border border-slate-800 rounded-3xl p-6 sm:p-8 backdrop-blur-2xl shadow-2xl relative z-10">
        <div className="text-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center mx-auto mb-3 shadow-xl shadow-blue-500/25">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white">SOC-IA Platform</h1>
          <p className="text-xs text-slate-400 mt-1">
            Autenticación Obligatoria RBAC contra PostgreSQL 15 (<code className="text-blue-400">soc_users</code>)
          </p>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Correo Institucional (PostgreSQL)
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="usuario@empresa.com"
                required
                autoFocus
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Contraseña (PBKDF2-SHA256)
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-blue-500/25 transition-all hover:scale-[1.01] disabled:opacity-50 cursor-pointer"
          >
            {isLoading ? (
              <span>Verificando en PostgreSQL 15...</span>
            ) : (
              <>
                <span>Iniciar Sesión en el SOC</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Quick Select Accounts from PostgreSQL */}
        <div className="mt-5 pt-4 border-t border-slate-800/80">
          <div className="flex items-center justify-between text-[11px] text-slate-400 mb-2">
            <span className="flex items-center gap-1.5 font-semibold text-slate-300">
              <Users className="w-3.5 h-3.5 text-blue-400" />
              Cuentas Iniciales en PostgreSQL (Clic para autocompletar):
            </span>
          </div>
          <div className="grid grid-cols-1 gap-1.5">
            {QUICK_ACCOUNTS.map((acc, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleFillAccount(acc)}
                className="flex items-center justify-between px-3 py-1.5 rounded-xl bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 text-left transition-colors cursor-pointer"
              >
                <div>
                  <div className="text-[11px] font-semibold text-slate-200">{acc.label}</div>
                  <div className="text-[10px] font-mono text-slate-400">{acc.email}</div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${acc.badge}`}>
                  Usar
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-800/60 text-center">
          <div className="flex items-center justify-center gap-1.5 text-[11px] text-slate-400">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Cada intento de acceso queda registrado en <code className="text-slate-300">audit_logs</code> (PostgreSQL).</span>
          </div>
        </div>
      </div>
    </div>
  );
}

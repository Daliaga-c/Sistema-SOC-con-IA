import React, { useState } from 'react';
import { Shield, KeyRound, Mail, Lock, ShieldCheck, ArrowRight, AlertCircle } from 'lucide-react';
import { login } from '../services/api';

export default function Login({ onLoginSuccess }) {
  const [email, setEmail] = useState('analista.soc@empresa.com');
  const [password, setPassword] = useState('soc-ia-2025');
  const [mfaCode, setMfaCode] = useState('482910');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email || !password || !mfaCode) {
      setError('Por favor completa todos los campos de autenticación.');
      return;
    }

    if (mfaCode.length !== 6 || !/^\d+$/.test(mfaCode)) {
      setError('El código MFA debe ser numérico de 6 dígitos.');
      return;
    }

    setIsLoading(true);
    try {
      const response = await login(email, password, mfaCode);
      const user = { ...response.user, token: response.token };
      localStorage.setItem('soc_session', JSON.stringify(user));
      onLoginSuccess(user);
    } catch (err) {
      setError(err.message || 'No se pudo iniciar sesión.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background glow effects */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-slate-900/80 border border-slate-800 rounded-3xl p-6 sm:p-8 backdrop-blur-2xl shadow-2xl relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center mx-auto mb-3 shadow-xl shadow-blue-500/25">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white">SOC-IA Platform</h1>
          <p className="text-xs text-slate-400 mt-1">Autenticación de Operador del Centro de Seguridad</p>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Correo Institucional
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analista@empresa.com"
                required
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Contraseña
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between items-center mb-1.5">
              <label className="text-xs font-medium text-slate-300">
                Código de Autenticación MFA (OTP)
              </label>
              <span className="text-[10px] text-blue-400 font-medium">TOTP / App</span>
            </div>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                maxLength={6}
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456"
                required
                className="w-full bg-slate-950/80 border border-slate-800 rounded-xl pl-10 pr-3.5 py-2.5 text-xs font-mono tracking-widest text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-blue-500/25 transition-all hover:scale-[1.01] disabled:opacity-50"
          >
            {isLoading ? (
              <span>Validando credenciales...</span>
            ) : (
              <>
                <span>Ingresar a la Consola</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Security Footer Note */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 text-center">
          <div className="flex items-center justify-center gap-1.5 text-[11px] text-slate-400">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Acceso restringido y auditado. Cumple con NIST SP 800-63B.</span>
          </div>
        </div>
      </div>
    </div>
  );
}

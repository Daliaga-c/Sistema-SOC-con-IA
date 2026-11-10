import React, { useState } from 'react';
import {
  Brain,
  X,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Flame,
  Terminal,
  Activity,
  Layers,
  Sparkles,
  Send,
  Cpu
} from 'lucide-react';
import { predictUserLog, ingestLogEvent } from '../services/api';

const SCENARIOS = [
  {
    name: 'Fuerza Bruta SSH (Wazuh 5712)',
    desc: '12 intentos fallidos hacia SSH con usuario root',
    data: {
      user: 'root',
      source_ip: '185.220.101.5',
      status: 'FAILURE',
      port: 22,
      failed_attempts: 12,
      service: 'ssh',
      source_system: 'Wazuh SIEM (Rule 5712)'
    }
  },
  {
    name: 'Login Legítimo de Usuario',
    desc: 'Autenticación exitosa normal en portal web',
    data: {
      user: 'daliaga',
      source_ip: '190.236.14.82',
      status: 'SUCCESS',
      port: 443,
      failed_attempts: 0,
      service: 'https',
      source_system: 'Portal Web'
    }
  },
  {
    name: 'Intrusión RDP Nocturna',
    desc: 'Ataque de diccionario a escritorio remoto',
    data: {
      user: 'Administrator',
      source_ip: '45.142.122.9',
      status: 'FAILURE',
      port: 3389,
      failed_attempts: 8,
      service: 'rdp',
      source_system: 'Wazuh SIEM (Rule 100003)'
    }
  },
  {
    name: 'Escalada de Privilegios SSH',
    desc: 'Fallo continuo en usuario privilegiado admin',
    data: {
      user: 'admin',
      source_ip: '192.168.1.150',
      status: 'FAILURE',
      port: 22,
      failed_attempts: 5,
      service: 'ssh',
      source_system: 'Wazuh Agent (Linux Auth)'
    }
  }
];

export default function LogPredictorModal({
  isOpen,
  onClose,
  onEscalateToAlert,
  onInvestigateInCopilot
}) {
  const [activeTab, setActiveTab] = useState('form'); // 'form', 'json', 'scenarios'
  const [formData, setFormData] = useState({
    user: 'root',
    source_ip: '185.220.101.5',
    status: 'FAILURE',
    port: 22,
    failed_attempts: 10,
    service: 'ssh',
    source_system: 'Wazuh SIEM'
  });

  const [rawJson, setRawJson] = useState(`{
  "timestamp": "2026-11-09T18:45:10Z",
  "rule": {
    "id": "5710",
    "level": 5,
    "description": "sshd: Attempt to login using a non-existent user"
  },
  "agent": {
    "id": "001",
    "name": "srv-ubuntu-prod",
    "ip": "10.0.0.15"
  },
  "data": {
    "srcip": "194.26.29.112",
    "dstuser": "root",
    "status": "FAILURE",
    "srcport": "41234"
  }
}`);

  const [isLoading, setIsLoading] = useState(false);
  const [predictionResult, setPredictionResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [isEscalating, setIsEscalating] = useState(false);
  const [escalatedOk, setEscalatedOk] = useState(false);

  if (!isOpen) return null;

  const handlePredict = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    setEscalatedOk(false);

    try {
      let payload;
      if (activeTab === 'json') {
        try {
          payload = JSON.parse(rawJson);
        } catch {
          throw new Error('El JSON ingresado no es válido. Verifica la sintaxis.');
        }
      } else {
        payload = { ...formData };
      }

      const result = await predictUserLog(payload);
      setPredictionResult(result);
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectScenario = (sc) => {
    setFormData(sc.data);
    setActiveTab('form');
  };

  const handleEscalate = async () => {
    if (!predictionResult) return;
    setIsEscalating(true);
    try {
      const summary = predictionResult.mapped_summary || {};
      const alertPayload = {
        user: summary.usuario || formData.user,
        ip_origen: summary.ip_origen || formData.source_ip,
        resultado: summary.estado || formData.status,
        origen: 'Predictor ML (modelo_soc.pkl)',
        dispositivo: `Puerto ${summary.puerto || formData.port} (${summary.servicio || formData.service})`,
        timestamp: new Date().toISOString()
      };

      await ingestLogEvent(alertPayload);
      setEscalatedOk(true);
      if (onEscalateToAlert) {
        onEscalateToAlert(alertPayload, predictionResult);
      }
    } catch (err) {
      setErrorMessage(`Error al escalar alerta: ${err.message}`);
    } finally {
      setIsEscalating(false);
    }
  };

  const handleInvestigateWithCopilot = () => {
    if (!predictionResult) return;
    const summary = predictionResult.mapped_summary || {};
    const alertData = {
      alert_id: `ALT-PREDICT-${Math.floor(1000 + Math.random() * 9000)}`,
      severity: predictionResult.severity || 'ALTA',
      status: 'NUEVA',
      raw_event: {
        user: summary.usuario || formData.user,
        source_ip: summary.ip_origen || formData.source_ip,
        source_system: 'Wazuh SIEM (modelo_soc.pkl Predictor)',
        status: summary.estado || formData.status
      },
      ml_score: {
        risk_score: predictionResult.risk_score,
        is_anomaly: predictionResult.is_anomaly,
        contributing_features: (predictionResult.contributing_factors || []).map(f => ({ factor: f, impacto: '+25%' }))
      },
      mitre_attack: ['T1110 - Brute Force', 'T1078 - Valid Accounts']
    };

    if (onInvestigateInCopilot) {
      onInvestigateInCopilot(alertData);
      onClose();
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    if (score >= 60) return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    if (score >= 40) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in duration-150">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl max-w-3xl w-full max-h-[90vh] shadow-2xl flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 bg-slate-950/70 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 text-indigo-400">
              <Brain className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white">Analizador & Predictor de Logs de Usuario</h3>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400">
                  modelo_soc.pkl (41-Feats)
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Inferencia con Random Forest de NSL-KDD adaptado a telemetría de Wazuh SIEM
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Navigation Tabs */}
        <div className="px-5 pt-3 bg-slate-950/30 border-b border-slate-800 flex gap-2">
          <button
            onClick={() => setActiveTab('form')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'form'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Formulario Rápido</span>
          </button>
          <button
            onClick={() => setActiveTab('json')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'json'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Pegar Log Crudo Wazuh (JSON)</span>
          </button>
          <button
            onClick={() => setActiveTab('scenarios')}
            className={`pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'scenarios'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Plantillas de Ataque</span>
          </button>
        </div>

        {/* Modal Body / Scrollable */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {/* TAB 1: FORM */}
          {activeTab === 'form' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1 font-medium">Usuario / Cuenta</label>
                <input
                  type="text"
                  value={formData.user}
                  onChange={(e) => setFormData({ ...formData, user: e.target.value })}
                  placeholder="ej: root, admin, daliaga"
                  className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">IP Origen</label>
                <input
                  type="text"
                  value={formData.source_ip}
                  onChange={(e) => setFormData({ ...formData, source_ip: e.target.value })}
                  placeholder="ej: 185.220.101.5"
                  className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Resultado de Autenticación</label>
                <select
                  value={formData.status}
                  onChange={(e) => setFormData({ ...formData, status: e.target.value })}
                  className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="FAILURE">FAILURE (Intento Fallido / Error)</option>
                  <option value="SUCCESS">SUCCESS (Autenticación Exitosa)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Intentos Fallidos Acumulados</label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={formData.failed_attempts}
                  onChange={(e) => setFormData({ ...formData, failed_attempts: parseInt(e.target.value) || 0 })}
                  className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Puerto de Red / Conexión</label>
                <input
                  type="number"
                  value={formData.port}
                  onChange={(e) => setFormData({ ...formData, port: parseInt(e.target.value) || 22 })}
                  className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-medium">Servicio Destino</label>
                <select
                  value={formData.service}
                  onChange={(e) => setFormData({ ...formData, service: e.target.value })}
                  className="w-full bg-slate-950/70 border border-slate-700/80 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="ssh">SSH (Puerto 22)</option>
                  <option value="https">HTTPS (Puerto 443)</option>
                  <option value="http">HTTP (Puerto 80)</option>
                  <option value="rdp">RDP (Puerto 3389)</option>
                  <option value="ftp">FTP (Puerto 21)</option>
                  <option value="other">Otro puerto personalizado</option>
                </select>
              </div>
            </div>
          )}

          {/* TAB 2: JSON RAW */}
          {activeTab === 'json' && (
            <div>
              <p className="text-xs text-slate-400 mb-2">
                Pega directamente la alerta en formato JSON emitida por Wazuh SIEM (<code className="text-blue-300 font-mono">alerts.json</code>) o por el webhook de Wazuh:
              </p>
              <textarea
                rows="8"
                value={rawJson}
                onChange={(e) => setRawJson(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl p-3 text-xs text-emerald-400 font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
          )}

          {/* TAB 3: SCENARIOS */}
          {activeTab === 'scenarios' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {SCENARIOS.map((sc, idx) => (
                <div
                  key={idx}
                  onClick={() => handleSelectScenario(sc)}
                  className="p-3 rounded-xl bg-slate-950/50 border border-slate-800 hover:border-blue-500/50 hover:bg-slate-800/40 cursor-pointer transition-all group"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-bold text-white group-hover:text-blue-400 transition-colors">
                      {sc.name}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                      Puerto {sc.data.port}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{sc.desc}</p>
                </div>
              ))}
            </div>
          )}

          {/* Predict Action Button */}
          <div className="pt-2 flex items-center justify-between">
            <button
              onClick={handlePredict}
              disabled={isLoading}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white text-xs font-bold shadow-lg shadow-indigo-500/25 transition-all hover:scale-[1.02] disabled:opacity-50 cursor-pointer"
            >
              <Play className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>{isLoading ? 'Calculando Inferencia...' : 'Predecir Riesgo con modelo_soc.pkl'}</span>
            </button>

            {predictionResult && (
              <span className="text-[11px] text-slate-400 font-mono">
                Motor: {predictionResult.model_engine}
              </span>
            )}
          </div>

          {/* Error Notice */}
          {errorMessage && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs">
              ⚠️ {errorMessage}
            </div>
          )}

          {/* RESULT BOX */}
          {predictionResult && (
            <div className="mt-4 p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-3.5 animate-in fade-in slide-in-from-top-2">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2.5">
                  {predictionResult.is_anomaly ? (
                    <div className="p-2 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-400">
                      <ShieldAlert className="w-5 h-5" />
                    </div>
                  ) : (
                    <div className="p-2 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">
                      <ShieldCheck className="w-5 h-5" />
                    </div>
                  )}
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-white tracking-wide">
                        {predictionResult.verdict}
                      </span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getScoreColor(predictionResult.risk_score)}`}>
                        Severidad {predictionResult.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Clasificación probabilística sobre las 41 variables canónicas de NSL-KDD
                    </p>
                  </div>
                </div>

                {/* Score Gauge */}
                <div className="flex items-baseline gap-1 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
                  <span className="text-[11px] text-slate-400 font-semibold">Risk Score:</span>
                  <span className={`text-lg font-black font-mono ${
                    predictionResult.risk_score >= 70 ? 'text-rose-400' :
                    predictionResult.risk_score >= 40 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {predictionResult.risk_score}%
                  </span>
                </div>
              </div>

              {/* Mapped Summary Pills */}
              {predictionResult.mapped_summary && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                  <div className="bg-slate-900/90 border border-slate-800/80 p-2 rounded-lg">
                    <span className="text-slate-400 block text-[10px]">Usuario</span>
                    <span className="font-mono font-semibold text-white truncate block">
                      {predictionResult.mapped_summary.usuario}
                    </span>
                  </div>
                  <div className="bg-slate-900/90 border border-slate-800/80 p-2 rounded-lg">
                    <span className="text-slate-400 block text-[10px]">IP Origen</span>
                    <span className="font-mono font-semibold text-white truncate block">
                      {predictionResult.mapped_summary.ip_origen}
                    </span>
                  </div>
                  <div className="bg-slate-900/90 border border-slate-800/80 p-2 rounded-lg">
                    <span className="text-slate-400 block text-[10px]">Servicio / Puerto</span>
                    <span className="font-mono font-semibold text-white truncate block">
                      {predictionResult.mapped_summary.servicio.toUpperCase()} ({predictionResult.mapped_summary.puerto})
                    </span>
                  </div>
                  <div className="bg-slate-900/90 border border-slate-800/80 p-2 rounded-lg">
                    <span className="text-slate-400 block text-[10px]">Intentos Fallidos</span>
                    <span className="font-mono font-semibold text-white">
                      {predictionResult.mapped_summary.intentos_fallidos}
                    </span>
                  </div>
                </div>
              )}

              {/* Factors list */}
              {predictionResult.contributing_factors && (
                <div>
                  <h4 className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-blue-400" />
                    <span>Factores Explicativos de la Decisión</span>
                  </h4>
                  <ul className="space-y-1 text-xs">
                    {predictionResult.contributing_factors.map((factor, idx) => (
                      <li key={idx} className="flex items-center gap-2 text-slate-300 bg-slate-900/50 px-2.5 py-1 rounded-md border border-slate-800/60">
                        <span className="text-blue-400">▸</span>
                        <span>{factor}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Action Buttons for Prediction */}
              <div className="pt-2 flex flex-wrap items-center justify-end gap-2 border-t border-slate-800/60">
                <button
                  onClick={handleInvestigateWithCopilot}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 text-xs font-semibold transition-colors cursor-pointer"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Investigar con Copilot IA</span>
                </button>

                {predictionResult.is_anomaly && (
                  <button
                    onClick={handleEscalate}
                    disabled={isEscalating || escalatedOk}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-lg shadow-rose-600/20 transition-all disabled:opacity-50 cursor-pointer"
                  >
                    <Flame className="w-3.5 h-3.5" />
                    <span>{escalatedOk ? '✅ Alerta Escalada al SOC' : (isEscalating ? 'Escalando...' : 'Escalar a Alerta Activa')}</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 bg-slate-950 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
          <span>Total variables procesadas en vector: 41</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold transition-colors"
          >
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
}

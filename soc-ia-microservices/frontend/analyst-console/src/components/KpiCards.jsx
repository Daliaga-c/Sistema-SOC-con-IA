import React from 'react';
import { ShieldAlert, AlertTriangle, Cpu, CheckCircle2 } from 'lucide-react';

export default function KpiCards({ alerts = [] }) {
  const total = alerts.length;
  const criticalAndHigh = alerts.filter(a => a.severity === 'CRÍTICA' || a.severity === 'ALTA').length;
  const avgRisk = total > 0
    ? (alerts.reduce((acc, a) => acc + (a.ml_score?.risk_score || 0), 0) / total).toFixed(1)
    : 0;
  const mitigatedCount = alerts.filter(a => a.status === 'CONTENIDA' || a.mitigation_status?.includes('EJECUTADA')).length;

  const cards = [
    {
      title: 'Total Alertas Procesadas',
      value: total,
      subtext: 'Telemetría SIEM & Logs Canónicos',
      icon: ShieldAlert,
      color: 'blue',
      textColor: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/20'
    },
    {
      title: 'Inicios de Sesión Anómalos',
      value: criticalAndHigh,
      subtext: 'Fuerza bruta & Accesos no autorizados',
      icon: AlertTriangle,
      color: 'rose',
      textColor: 'text-rose-400',
      bgColor: 'bg-rose-500/10',
      borderColor: 'border-rose-500/20'
    },
    {
      title: 'Riesgo Promedio de Inferencia',
      value: `${avgRisk}%`,
      subtext: 'Evaluación estadística por ML',
      icon: Cpu,
      color: 'amber',
      textColor: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/20'
    },
    {
      title: 'Mitigaciones Asistidas (HITL)',
      value: mitigatedCount,
      subtext: 'Bloqueos con firma de analista',
      icon: CheckCircle2,
      color: 'emerald',
      textColor: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/20'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={i}
            className={`p-4 rounded-2xl bg-slate-900/50 border ${card.borderColor} backdrop-blur-md shadow-lg shadow-black/20 flex flex-col justify-between`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium text-slate-400">{card.title}</span>
              <div className={`p-2 rounded-xl ${card.bgColor} ${card.textColor}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>
            <div>
              <div className={`text-2xl font-extrabold ${card.textColor} tracking-tight mb-1`}>
                {card.value}
              </div>
              <p className="text-[11px] text-slate-500">{card.subtext}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

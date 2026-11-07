import React from 'react';
import { AlertTriangle, Flame, ShieldAlert, Cpu } from 'lucide-react';

export default function KpiMetrics({ alerts }) {
  const total = alerts.length;
  const critical = alerts.filter(a => a.severity === 'CRÍTICA').length;
  const anomalies = alerts.filter(a => a.ml_score?.is_anomaly).length;
  const avgRisk = total > 0
    ? (alerts.reduce((acc, curr) => acc + (curr.ml_score?.risk_score || 0), 0) / total).toFixed(1)
    : 0;

  const cards = [
    {
      label: 'Total Incidentes Registrados',
      value: total,
      sub: 'Eventos correlacionados en tiempo real',
      icon: AlertTriangle,
      color: 'text-blue-400',
      border: 'border-blue-500/20',
      bg: 'bg-blue-500/5'
    },
    {
      label: 'Alertas Críticas P1',
      value: critical,
      sub: 'Requieren mitigación activa inmediata',
      icon: Flame,
      color: 'text-rose-400',
      border: 'border-rose-500/30',
      bg: 'bg-rose-500/10'
    },
    {
      label: 'Anomalías Confirmadas por ML',
      value: anomalies,
      sub: 'Desviaciones estadísticas de comportamiento',
      icon: Cpu,
      color: 'text-amber-400',
      border: 'border-amber-500/20',
      bg: 'bg-amber-500/5'
    },
    {
      label: 'Puntaje de Riesgo Promedio',
      value: `${avgRisk} / 100`,
      sub: 'Índice de severidad del entorno',
      icon: ShieldAlert,
      color: 'text-emerald-400',
      border: 'border-emerald-500/20',
      bg: 'bg-emerald-500/5'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {cards.map((c, i) => {
        const Icon = c.icon;
        return (
          <div
            key={i}
            className={`p-4 rounded-xl border ${c.border} ${c.bg} backdrop-blur-md flex flex-col justify-between`}
          >
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span>{c.label}</span>
              <Icon className={`w-4 h-4 ${c.color}`} />
            </div>
            <div className={`text-2xl font-bold font-mono tracking-tight ${c.color} mb-1`}>
              {c.value}
            </div>
            <div className="text-[11px] text-slate-500">
              {c.sub}
            </div>
          </div>
        );
      })}
    </div>
  );
}


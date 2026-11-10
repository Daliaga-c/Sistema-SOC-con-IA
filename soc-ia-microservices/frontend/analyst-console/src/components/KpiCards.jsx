import React from 'react';
import { ShieldAlert, AlertTriangle, Cpu, CheckCircle2, Radio, FileText } from 'lucide-react';

export default function KpiCards({ alerts = [], metrics = null }) {
  const totalAlerts = metrics?.alerts?.total ?? alerts.length;
  const criticalAndHigh =
    metrics?.alerts?.critical_and_high ??
    alerts.filter((a) => a.severity === 'CRÍTICA' || a.severity === 'ALTA').length;
  const avgRisk =
    metrics?.alerts?.avg_risk_score ??
    (alerts.length > 0
      ? (alerts.reduce((acc, a) => acc + (a.ml_score?.risk_score || 0), 0) / alerts.length).toFixed(1)
      : 0);
  const mitigatedCount =
    metrics?.alerts?.contained ??
    alerts.filter((a) => a.status === 'CONTENIDA' || a.mitigation_status?.includes('EJECUTADA')).length;
  const wazuhBuffered = metrics?.wazuh_buffer_total ?? 0;
  const auditLogsCount = metrics?.audit_logs_total ?? 0;

  const cards = [
    {
      title: 'Alertas Activas (PostgreSQL)',
      value: totalAlerts,
      subtext: `${criticalAndHigh} Críticas / Altas detectadas`,
      icon: ShieldAlert,
      textColor: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/20'
    },
    {
      title: 'Eventos en Buffer Wazuh SIEM',
      value: wazuhBuffered,
      subtext: 'Tabla wazuh_raw_events (PostgreSQL)',
      icon: Radio,
      textColor: 'text-purple-400',
      bgColor: 'bg-purple-500/10',
      borderColor: 'border-purple-500/20'
    },
    {
      title: 'Riesgo Promedio (modelo_soc.pkl)',
      value: `${avgRisk}%`,
      subtext: 'Random Forest 41-features NSL-KDD',
      icon: Cpu,
      textColor: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/20'
    },
    {
      title: 'Mitigaciones & Registros Forenses',
      value: `${mitigatedCount} / ${auditLogsCount}`,
      subtext: 'Contenciones HITL / Total audit_logs',
      icon: CheckCircle2,
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
            className={`p-4 rounded-2xl bg-slate-900/60 border ${card.borderColor} backdrop-blur-md shadow-lg shadow-black/20 flex flex-col justify-between`}
          >
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-xs font-medium text-slate-400">{card.title}</span>
              <div className={`p-2 rounded-xl ${card.bgColor} ${card.textColor}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>
            <div>
              <div className={`text-2xl font-extrabold ${card.textColor} tracking-tight mb-0.5`}>
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

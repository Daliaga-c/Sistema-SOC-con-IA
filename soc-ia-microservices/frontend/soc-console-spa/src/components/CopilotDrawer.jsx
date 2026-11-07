import React, { useState, useEffect, useRef } from 'react';
import { Bot, Send, X, Shield, Sparkles } from 'lucide-react';
import { sendCopilotMessage } from '../services/api';

export default function CopilotDrawer({ alert, onClose, onMitigate }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (alert) {
      setMessages([
        {
          role: 'assistant',
          text: `Hola Analista. He cargado el contexto del incidente **${alert.alert_id}** (${alert.title}). 
- **IP sospechosa:** \`${alert.raw_event?.source_ip}\`
- **Puntaje ML:** **${alert.ml_score?.risk_score} / 100**
- **Táctica MITRE:** \`${alert.mitre_attack?.join(', ')}\`

¿Deseas que analice los factores determinantes o preparemos la orden de Active Response para Wazuh?`
        }
      ]);
    }
  }, [alert]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSend = async (textToSend = null) => {
    const text = textToSend || input;
    if (!text.trim() || loading) return;

    const newMessages = [...messages, { role: 'user', text }];
    setMessages(newMessages);
    setInput('');
    setLoading(true);

    try {
      const res = await sendCopilotMessage(text, alert);
      setMessages([...newMessages, { role: 'assistant', text: res.reply || 'Sin respuesta.' }]);
    } catch (err) {
      setMessages([
        ...newMessages,
        { role: 'assistant', text: '⚠️ No se pudo comunicar con el microservicio de Copilot IA (Puerto 8005).' }
      ]);
    } finally {
      setLoading(false);
    }
  };

  if (!alert) return null;

  return (
    <div className="w-full lg:w-96 rounded-xl border border-white/10 bg-[#121826]/95 backdrop-blur-md flex flex-col h-[700px] overflow-hidden shadow-2xl">
      {/* Header */}
      <div className="p-3.5 border-b border-white/10 bg-[#0d131f] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30 flex items-center justify-center">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs font-bold text-white flex items-center gap-1.5">
              <span>SOC-IA Copilot</span>
              <Sparkles className="w-3 h-3 text-amber-400" />
            </h2>
            <p className="text-[10px] text-slate-400 font-mono">
              Contexto: {alert.alert_id}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Factores de Riesgo */}
      {alert.ml_score?.contributing_features && (
        <div className="p-3 bg-white/[0.02] border-b border-white/5 text-[11px]">
          <div className="font-semibold text-slate-300 mb-1.5">Factores Clave de Detección:</div>
          <div className="space-y-1">
            {alert.ml_score.contributing_features.map((f, i) => (
              <div key={i} className="flex justify-between text-slate-400 font-mono">
                <span>&bull; {f.factor}</span>
                <span className="text-rose-400 font-bold">{f.impacto}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Chat Messages */}
      <div ref={scrollRef} className="flex-1 p-3.5 overflow-y-auto space-y-3 text-xs">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`p-3 rounded-xl max-w-[90%] leading-relaxed ${
                m.role === 'user'
                  ? 'bg-blue-600 text-white rounded-br-none'
                  : 'bg-white/5 text-slate-200 border border-white/10 rounded-bl-none'
              }`}
            >
              <div className="whitespace-pre-wrap">{m.text}</div>
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 text-xs italic">
            <Bot className="w-3.5 h-3.5 animate-bounce text-blue-400" />
            <span>El Copiloto IA está razonando...</span>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="px-3 py-2 border-t border-white/5 bg-[#0d131f]/60 flex gap-1.5 overflow-x-auto text-[10px]">
        <button
          onClick={() => handleSend('¿Cuál es el vector de ataque según MITRE?')}
          className="whitespace-nowrap px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10"
        >
          Vector MITRE
        </button>
        <button
          onClick={() => handleSend('¿Recomiendas bloquear esta IP o es falso positivo?')}
          className="whitespace-nowrap px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10"
        >
          Análisis FP / TP
        </button>
      </div>

      {/* Input */}
      <div className="p-3 border-t border-white/10 bg-[#0d131f] flex gap-2">
        <input
          type="text"
          placeholder="Escribe tu consulta al Copiloto..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-blue-500"
        />
        <button
          onClick={() => handleSend()}
          disabled={loading}
          className="px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center justify-center transition-all disabled:opacity-50"
        >
          <Send className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}


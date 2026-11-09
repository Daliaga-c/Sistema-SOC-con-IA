import React, { useState, useRef, useEffect } from 'react';
import { Bot, Send, X, Sparkles, ShieldAlert, CheckCircle, ExternalLink } from 'lucide-react';

export default function CopilotChat({
  isOpen,
  onClose,
  activeAlert,
  messages,
  onSendMessage,
  onTriggerMitigation,
  isSending
}) {
  const [inputMessage, setInputMessage] = useState('');
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || isSending) return;
    onSendMessage(inputMessage);
    setInputMessage('');
  };

  const handleQuickQuestion = (q) => {
    onSendMessage(q);
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full sm:w-[460px] bg-slate-900/95 border-l border-slate-800 shadow-2xl backdrop-blur-2xl z-50 flex flex-col transition-all animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-purple-600 to-blue-600 flex items-center justify-center text-white shadow-md shadow-purple-500/20">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
              <span>SOC Copilot</span>
              <span className="text-[10px] font-semibold px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                RAG + NIST
              </span>
            </h3>
            <span className="text-[11px] text-emerald-400 font-medium">● En línea (Gemini 2.0)</span>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Context Badge if investigating specific alert */}
      {activeAlert && (
        <div className="px-4 py-2 bg-blue-950/30 border-b border-blue-900/30 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-blue-400">Contexto Alerta:</span>
            <span className="font-mono text-slate-200">{activeAlert.alert_id}</span>
            <span className="text-slate-400">({activeAlert.raw_event?.user} @ {activeAlert.raw_event?.source_ip})</span>
          </div>
        </div>
      )}

      {/* Messages Stream */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3.5">
        {messages.map((msg, idx) => {
          const isCopilot = msg.sender === 'copilot';
          return (
            <div
              key={idx}
              className={`flex flex-col ${isCopilot ? 'items-start' : 'items-end'}`}
            >
              <div
                className={`max-w-[90%] p-3.5 rounded-2xl text-xs leading-relaxed whitespace-pre-wrap ${
                  isCopilot
                    ? 'bg-slate-800/80 border border-slate-700/60 text-slate-100 shadow-md'
                    : 'bg-blue-600 text-white rounded-br-none shadow-md shadow-blue-500/20'
                }`}
              >
                {msg.text}

                {/* If the Copilot suggests mitigation, show actionable button */}
                {msg.recommended_action && (
                  <div className="mt-3 pt-3 border-t border-slate-700/60">
                    <div className="text-[11px] font-semibold text-rose-300 mb-1.5 flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      Acción Recomendada por IA:
                    </div>
                    <button
                      onClick={() => onTriggerMitigation(msg.recommended_action, msg.target)}
                      className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition-colors shadow-sm"
                    >
                      Aprobar Bloqueo en Firewall ({msg.target})
                    </button>
                  </div>
                )}
              </div>
              <span className="text-[10px] text-slate-500 mt-1 px-1">
                {msg.timestamp || 'Ahora'}
              </span>
            </div>
          );
        })}
        {isSending && (
          <div className="flex items-center gap-2 text-slate-400 text-xs py-2">
            <Bot className="w-4 h-4 animate-spin text-purple-400" />
            <span>El Copilot está razonando con NIST & MITRE...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts */}
      <div className="px-4 py-2 border-t border-slate-800/60 bg-slate-950/30 flex items-center gap-1.5 overflow-x-auto text-[11px]">
        <button
          onClick={() => handleQuickQuestion('Explica la técnica MITRE detectada')}
          className="whitespace-nowrap px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
        >
          🔍 ¿Qué técnica MITRE es?
        </button>
        <button
          onClick={() => handleQuickQuestion('¿Cuál es el playbook NIST de contención?')}
          className="whitespace-nowrap px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
        >
          📘 Playbook NIST
        </button>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="p-3.5 border-t border-slate-800 bg-slate-950/60">
        <div className="relative flex items-center">
          <input
            type="text"
            placeholder="Pregunta sobre la alerta, técnicas MITRE o playbooks..."
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            disabled={isSending}
            className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-3.5 pr-11 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
          />
          <button
            type="submit"
            disabled={!inputMessage.trim() || isSending}
            className="absolute right-1.5 p-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white disabled:opacity-40 transition-colors"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>
    </div>
  );
}

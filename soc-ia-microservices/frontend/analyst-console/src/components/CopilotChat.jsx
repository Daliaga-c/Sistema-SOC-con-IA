import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  Send,
  X,
  ShieldAlert,
  Cpu,
  AlertTriangle,
  Wrench,
  HelpCircle,
  Minus,
  ChevronUp,
  Sparkles
} from 'lucide-react';

export default function CopilotChat({
  isOpen,
  onClose,
  activeAlert,
  messages,
  onSendMessage,
  onTriggerMitigation,
  isSending,
  copilotStatus
}) {
  const [inputMessage, setInputMessage] = useState('');
  const [isMinimized, setIsMinimized] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (!isMinimized) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isMinimized]);

  // Si se abre o cambia de alerta, asegurarse de que no esté minimizado
  useEffect(() => {
    if (activeAlert) {
      setIsMinimized(false);
    }
  }, [activeAlert]);

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || isSending) return;
    onSendMessage(inputMessage);
    setInputMessage('');
  };

  const geminiUp = copilotStatus?.gemini?.available;
  const ollamaUp = copilotStatus?.ollama?.available;
  const isAnyOnline = geminiUp || ollamaUp;
  const statusLabel = geminiUp
    ? `Gemini (${copilotStatus?.gemini?.model || 'Cloud'})`
    : ollamaUp
    ? `Ollama Local (${copilotStatus?.ollama?.active_model || 'qwen2.5:0.5b'})`
    : 'Offline (HTTP 503)';

  // ESTADO MINIMIZADO: Píldora compacta flotante en la esquina inferior derecha
  if (isMinimized) {
    return (
      <aside
        onClick={() => setIsMinimized(false)}
        className="fixed bottom-5 right-5 z-40 bg-gradient-to-r from-purple-800/95 via-indigo-800/95 to-slate-900/95 border border-purple-500/40 text-white px-4 py-2.5 rounded-full shadow-2xl flex items-center gap-2.5 cursor-pointer hover:scale-105 hover:border-purple-400 transition-all backdrop-blur-xl animate-in fade-in slide-in-from-bottom-2 select-none"
        title="Clic para expandir el asistente SOC Copilot"
      >
        <div className="w-6 h-6 rounded-full bg-purple-600 flex items-center justify-center text-white shrink-0">
          <Bot className="w-3.5 h-3.5" />
        </div>
        <div className="flex items-center gap-1.5 text-xs font-bold">
          <span>SOC Copilot</span>
          {activeAlert && (
            <span className="font-mono text-[10px] text-purple-200 bg-purple-950/70 px-2 py-0.5 rounded-md border border-purple-500/30">
              {activeAlert.alert_id}
            </span>
          )}
        </div>
        <ChevronUp className="w-4 h-4 text-purple-300 ml-1" />
      </aside>
    );
  }

  // ESTADO EXPANDIDO: Mini Pop-Up flotante a la derecha (estético, no rompe la tabla ni tapa botones superiores)
  return (
    <aside className="fixed bottom-5 right-5 z-40 w-[92vw] sm:w-[420px] md:w-[440px] h-[580px] max-h-[84vh] bg-slate-900/95 border border-slate-700/80 rounded-2xl shadow-2xl shadow-black/60 backdrop-blur-2xl flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-3 duration-200">
      {/* Header del Mini Pop-Up */}
      <div className="p-3 border-b border-slate-800/90 flex items-center justify-between bg-slate-950/85">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-purple-600 to-blue-600 flex items-center justify-center text-white shadow-md shadow-purple-500/20 shrink-0">
            <Bot className="w-3.5 h-3.5" />
          </div>
          <div className="min-w-0">
            <h3 className="text-xs font-bold text-white flex items-center gap-1.5 truncate">
              <span>SOC Copilot</span>
              <span className="text-[9px] font-semibold px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                Mini Pop-Up
              </span>
            </h3>
            <span
              className={`text-[10px] font-medium flex items-center gap-1 truncate ${
                isAnyOnline ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              <span>●</span>
              <span className="truncate">{statusLabel}</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {/* Botón Minimizar */}
          <button
            onClick={() => setIsMinimized(true)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            title="Minimizar a píldora flotante (para ver toda la tabla)"
          >
            <Minus className="w-3.5 h-3.5" />
          </button>
          {/* Botón Cerrar */}
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            title="Cerrar Copilot"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Context Badge */}
      {activeAlert ? (
        <div className="px-3 py-1.5 bg-blue-950/40 border-b border-blue-900/40 flex items-center justify-between gap-2 text-[11px]">
          <div className="flex items-center gap-1.5 truncate">
            <span className="font-bold text-blue-400">Triaje:</span>
            <span className="font-mono text-slate-200 font-semibold">{activeAlert.alert_id}</span>
            <span className="text-slate-400 truncate">({activeAlert.raw_event?.user} @ {activeAlert.raw_event?.source_ip})</span>
          </div>
        </div>
      ) : (
        <div className="px-3 py-1 bg-slate-950/50 border-b border-slate-800 text-[10px] text-slate-400 flex items-center gap-1.5">
          <HelpCircle className="w-3 h-3 text-purple-400 shrink-0" />
          <span>Haz clic en "Investigar" en cualquier fila para diagnosticarla aquí.</span>
        </div>
      )}

      {/* Stream de Mensajes */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
        {messages.map((msg, idx) => {
          const isCopilot = msg.sender === 'copilot';
          const isError = msg.isError;
          return (
            <div key={idx} className={`flex flex-col ${isCopilot ? 'items-start' : 'items-end'}`}>
              <div
                className={`max-w-[94%] p-3 rounded-2xl text-xs leading-relaxed whitespace-pre-wrap ${
                  isError
                    ? 'bg-rose-950/60 border border-rose-500/40 text-rose-200 shadow-md'
                    : isCopilot
                    ? 'bg-slate-800/90 border border-slate-700/60 text-slate-100 shadow-md'
                    : 'bg-blue-600 text-white rounded-br-none shadow-md shadow-blue-500/20'
                }`}
              >
                {isCopilot && (msg.provider || msg.model) && (
                  <div className="flex items-center justify-between gap-1.5 mb-1.5 pb-1 border-b border-slate-700/50 text-[10px] font-mono text-purple-300">
                    <span className="flex items-center gap-1">
                      <Cpu className="w-3 h-3 text-purple-400" />
                      {msg.provider} ({msg.model})
                    </span>
                    {msg.intent_mode && (
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                          msg.intent_mode === 'SOLUCION_Y_MITIGACION'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                        }`}
                      >
                        {msg.intent_mode === 'SOLUCION_Y_MITIGACION' ? 'MODO SOLUCIÓN' : 'DIAGNÓSTICO'}
                      </span>
                    )}
                  </div>
                )}

                {isError && (
                  <div className="flex items-center gap-1.5 mb-1.5 text-rose-400 font-bold text-xs">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Error de Disponibilidad LLM</span>
                  </div>
                )}

                {msg.text}

                {/* Botón de Mitigación (SOLO aparece tras pedir la solución) */}
                {msg.recommended_action && (
                  <div className="mt-2.5 pt-2 border-t border-slate-700/60">
                    <div className="text-[11px] font-semibold text-rose-300 mb-1 flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      Solución Lista (Human-in-the-Loop):
                    </div>
                    <button
                      onClick={() => onTriggerMitigation(msg.recommended_action, msg.target)}
                      className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition-colors shadow-sm cursor-pointer"
                    >
                      Abrir Modal de Mitigación ({msg.target})
                    </button>
                  </div>
                )}

                {/* Botón "¿Cómo lo soluciono?" si fue solo un diagnóstico */}
                {isCopilot && !isError && !msg.recommended_action && activeAlert && idx === messages.length - 1 && (
                  <div className="mt-2 pt-2 border-t border-slate-700/50 flex flex-wrap items-center justify-between gap-1.5">
                    <span className="text-[10px] text-slate-400">
                      ¿Requiere contención?
                    </span>
                    <button
                      onClick={() =>
                        onSendMessage(
                          `¿Cómo lo solucionamos? Dame los pasos de mitigación y contención para la alerta ${activeAlert.alert_id}.`
                        )
                      }
                      disabled={isSending}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-purple-600/30 hover:bg-purple-600 text-purple-200 hover:text-white border border-purple-500/40 text-[10px] font-semibold transition-colors cursor-pointer"
                    >
                      <Wrench className="w-3 h-3" />
                      <span>¿Cómo lo soluciono?</span>
                    </button>
                  </div>
                )}
              </div>
              <span className="text-[9px] text-slate-500 mt-0.5 px-1">{msg.timestamp || 'Ahora'}</span>
            </div>
          );
        })}
        {isSending && (
          <div className="flex items-center gap-2 text-slate-300 text-xs py-2 px-2.5 bg-slate-800/40 rounded-xl border border-slate-800">
            <Bot className="w-4 h-4 animate-spin text-purple-400 shrink-0" />
            <span>Consultando RAG NIST/MITRE y motor LLM...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Prompts Rápidos Progresivos */}
      <div className="px-3 py-1.5 border-t border-slate-800 bg-slate-950/70 flex flex-wrap items-center gap-1 text-[10px]">
        <button
          onClick={() =>
            onSendMessage('¿A qué se debe esta alerta y por qué se activó la regla en Wazuh?')
          }
          disabled={isSending}
          className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 border border-slate-700 transition-colors cursor-pointer"
        >
          1️⃣ ¿Causa Raíz?
        </button>
        <button
          onClick={() =>
            onSendMessage('Evalúa si este evento es un Falso Positivo operativo o un Verdadero Positivo.')
          }
          disabled={isSending}
          className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 border border-slate-700 transition-colors cursor-pointer"
        >
          2️⃣ ¿FP o Ataque?
        </button>
        <button
          onClick={() =>
            onSendMessage('¿Cómo lo soluciono? Dame el plan de mitigación y habilita la acción de bloqueo.')
          }
          disabled={isSending}
          className="px-2 py-0.5 rounded-full bg-rose-950/80 text-rose-300 hover:text-white hover:bg-rose-600 border border-rose-500/40 font-semibold transition-colors cursor-pointer"
        >
          3️⃣ ¿Cómo solucionarlo?
        </button>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="p-2.5 border-t border-slate-800 bg-slate-950/90">
        <div className="relative flex items-center">
          <input
            type="text"
            placeholder="Pregunta o escribe '¿cómo lo soluciono?'..."
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            disabled={isSending}
            className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-3 pr-10 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 transition-colors"
          />
          <button
            type="submit"
            disabled={!inputMessage.trim() || isSending}
            className="absolute right-1 p-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white disabled:opacity-40 transition-colors cursor-pointer"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>
    </aside>
  );
}

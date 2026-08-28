import React from 'react';
import { Shield, CheckCircle2, Loader2, AlertCircle, Terminal, Cpu } from 'lucide-react';
import { AnalysisStages } from '../../services/api';

export function AnalysisProgressModal({
  isOpen,
  currentStageIndex,
  isMock = false,
  error = null,
  onRetry,
}) {
  if (!isOpen) return null;

  const currentPercent = Math.min(100, Math.round(((currentStageIndex + 1) / AnalysisStages.length) * 100));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0a0d14]/85 backdrop-blur-xl animate-fadeIn">
      <div className="relative w-full max-w-xl bg-[#111726] border border-cyan-500/30 rounded-2xl p-6 sm:p-8 shadow-2xl shadow-cyan-950/50 overflow-hidden">
        {/* Subtle cyber background grid & glow */}
        <div className="absolute -top-24 -right-24 w-60 h-60 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-60 h-60 bg-violet-500/10 rounded-full blur-3xl pointer-events-none" />

        {/* Modal Header */}
        <div className="flex items-center justify-between pb-5 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/60 border border-cyan-700/50 text-cyan-400">
              <Cpu className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <h2 className="text-base font-bold font-mono tracking-wider text-slate-100 uppercase">
                DEEP FORENSIC INVESTIGATION PIPELINE
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                {isMock ? 'Simulating threat correlation memory...' : 'Executing multi-module analysis (M1 → M2 → M3)...'}
              </p>
            </div>
          </div>
          <div className="text-right font-mono">
            <span className="text-lg font-extrabold text-cyan-400">{currentPercent}%</span>
            <span className="block text-[10px] text-slate-500 uppercase tracking-wider">PROGRESS</span>
          </div>
        </div>

        {/* Linear Progress Bar */}
        <div className="w-full bg-slate-900 rounded-full h-2 mt-5 overflow-hidden border border-slate-800">
          <div
            className="bg-gradient-to-r from-cyan-500 via-sky-400 to-indigo-500 h-2 rounded-full transition-all duration-300 ease-out shadow-sm shadow-cyan-400/50"
            style={{ width: `${currentPercent}%` }}
          />
        </div>

        {/* Forensic Stages Checklist */}
        <div className="mt-6 space-y-2.5 max-h-72 overflow-y-auto pr-1">
          {AnalysisStages.map((stage, idx) => {
            const isCompleted = idx < currentStageIndex;
            const isCurrent = idx === currentStageIndex;
            const isPending = idx > currentStageIndex;

            return (
              <div
                key={stage.id}
                className={`flex items-center justify-between p-2.5 rounded-lg border text-xs font-mono transition-all ${
                  isCompleted
                    ? 'bg-slate-900/60 border-slate-800/80 text-emerald-300'
                    : isCurrent
                    ? 'bg-cyan-950/30 border-cyan-600/50 text-cyan-200 shadow-sm shadow-cyan-950/40'
                    : 'bg-slate-900/20 border-slate-800/40 text-slate-500 opacity-60'
                }`}
              >
                <div className="flex items-center gap-3">
                  {isCompleted ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : isCurrent ? (
                    <Loader2 className="w-4 h-4 text-cyan-400 animate-spin shrink-0" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-700 flex items-center justify-center text-[10px] text-slate-600 shrink-0">
                      {idx + 1}
                    </div>
                  )}
                  <span className={isCurrent ? 'font-semibold text-slate-100' : ''}>
                    {stage.label}
                  </span>
                </div>

                <span className="text-[10px] uppercase tracking-wider font-semibold">
                  {isCompleted && <span className="text-emerald-400">DONE</span>}
                  {isCurrent && <span className="text-cyan-400 animate-pulse">PROCESSING</span>}
                  {isPending && <span className="text-slate-600">QUEUED</span>}
                </span>
              </div>
            );
          })}
        </div>

        {/* Error Notification if any */}
        {error && (
          <div className="mt-5 p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400" />
              <span>{error}</span>
            </div>
            {onRetry && (
              <button
                onClick={onRetry}
                className="px-2.5 py-1 bg-rose-800 hover:bg-rose-700 text-white rounded text-[11px] font-mono"
              >
                Retry
              </button>
            )}
          </div>
        )}

        {/* Footer info */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
          <div className="flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-500" />
            <span>AI Forensics Correlator v2.4</span>
          </div>
          <span>Autonomous Pipeline</span>
        </div>
      </div>
    </div>
  );
}

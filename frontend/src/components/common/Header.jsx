import React, { useState, useEffect } from 'react';
import { Shield, Activity, Database, Cpu, Terminal, Radio, Server } from 'lucide-react';
import { Badge } from './Badge';
import { checkServicesHealth } from '../../services/api';

export function Header({
  activeView,
  setActiveView,
  mockMode,
  setMockMode,
  analysisResult,
}) {
  const [serviceHealth, setServiceHealth] = useState({
    member1: { online: false },
    member2: { online: false },
    member3: { online: false },
  });

  useEffect(() => {
    let isMounted = true;
    checkServicesHealth().then((health) => {
      if (isMounted) {
        setServiceHealth(health);
      }
    });
    return () => {
      isMounted = false;
    };
  }, []);

  const mode = analysisResult?.mode || (mockMode ? 'mock' : 'live');
  const provenance = analysisResult?.provenance || {};

  const getModeBadge = () => {
    if (mode === 'live') {
      return <Badge variant="low" dot size="xs">LIVE SERVICES</Badge>;
    }
    if (mode === 'partial_live') {
      return <Badge variant="high" dot size="xs">PARTIAL LIVE</Badge>;
    }
    if (mode === 'fallback_mock') {
      return <Badge variant="medium" dot size="xs">FALLBACK INTELLIGENCE</Badge>;
    }
    return <Badge variant="dna" dot size="xs">DEMO / MOCK MODE</Badge>;
  };

  return (
    <header className="sticky top-0 z-40 w-full bg-[#0a0d14]/90 backdrop-blur-xl border-b border-slate-800/80 px-4 lg:px-8 py-3 transition-colors print:hidden">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand & Mission Title */}
        <div className="flex items-center gap-3.5 cursor-pointer" onClick={() => setActiveView('upload')}>
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-cyan-600/10 to-transparent border border-cyan-500/40 text-cyan-400 shadow-lg shadow-cyan-500/10">
            <Shield className="w-5 h-5" />
            <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-wider text-slate-100 uppercase font-mono">
                EMAIL THREAT FORENSICS AI
              </h1>
              <Badge variant="info" size="xs">SOC v2.4</Badge>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Autonomous Forensics, AI Threat Detection & Threat Intelligence
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center p-1 rounded-xl bg-[#111726] border border-slate-800 shadow-inner overflow-x-auto max-w-full">
          <button
            onClick={() => setActiveView('upload')}
            className={`px-3 sm:px-4 py-1.5 rounded-lg text-xs font-semibold font-mono tracking-wide whitespace-nowrap transition-all ${
              activeView === 'upload'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            01. INGEST
          </button>
          <button
            onClick={() => setActiveView('dashboard')}
            className={`px-3 sm:px-4 py-1.5 rounded-lg text-xs font-semibold font-mono tracking-wide whitespace-nowrap transition-all ${
              activeView === 'dashboard'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            02. DASHBOARD
          </button>
          <button
            onClick={() => setActiveView('investigation')}
            className={`px-3 sm:px-4 py-1.5 rounded-lg text-xs font-semibold font-mono tracking-wide whitespace-nowrap transition-all ${
              activeView === 'investigation'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            03. GRAPH & TIMELINE
          </button>
          <button
            onClick={() => setActiveView('report')}
            className={`px-3 sm:px-4 py-1.5 rounded-lg text-xs font-semibold font-mono tracking-wide whitespace-nowrap transition-all ${
              activeView === 'report'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            04. FORENSIC REPORT
          </button>
        </nav>

        {/* Microservice & Engine Telemetry Badges */}
        <div className="flex items-center gap-2.5">
          {analysisResult?.id && (
            <div className="hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-300">
              <Radio className="w-3 h-3 animate-pulse text-cyan-400" />
              <span>{analysisResult.id}</span>
            </div>
          )}

          {/* Mode & Provenance Badge */}
          {getModeBadge()}

          {/* Mode Switch */}
          <button
            onClick={() => setMockMode(!mockMode)}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[11px] font-mono transition-all ${
              mockMode
                ? 'bg-amber-950/40 border-amber-800/80 text-amber-300 hover:bg-amber-900/40'
                : 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300 hover:bg-emerald-900/40'
            }`}
            title="Toggle between Live Microservices and Offline Mock Threat Memory"
          >
            <Activity className="w-3 h-3" />
            <span className="hidden sm:inline">{mockMode ? 'MOCK MEMORY' : 'LIVE SERVICES'}</span>
          </button>
        </div>
      </div>
    </header>
  );
}

import React, { useState } from 'react';
import { 
  Network, 
  ArrowLeft, 
  Calendar, 
  GitMerge, 
  Layers, 
  FileText, 
  Printer, 
  Cpu
} from 'lucide-react';
import { Button } from '../components/common/Button';
import { Badge } from '../components/common/Badge';
import { CampaignGraphCanvas } from '../components/investigation/CampaignGraphCanvas';
import { InfrastructureTimeline } from '../components/investigation/InfrastructureTimeline';
import { ProbableAttackPath } from '../components/investigation/ProbableAttackPath';
import { EvidenceProvenanceChain } from '../components/investigation/EvidenceProvenanceChain';
import { InvestigationCaseSummary } from '../components/investigation/InvestigationCaseSummary';

export function InvestigationView({
  analysisResult,
  onBackToDashboard,
  onViewReport,
  onReset,
}) {
  const [activeTab, setActiveTab] = useState('graph'); // 'graph' | 'timeline' | 'attack_path' | 'provenance' | 'case_summary'

  if (!analysisResult) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center text-center p-6">
        <Network className="w-12 h-12 text-slate-600 mb-4 animate-pulse" />
        <h2 className="text-xl font-bold font-mono text-slate-300">NO ACTIVE INVESTIGATION TOPOLOGY</h2>
        <p className="text-sm text-slate-500 mt-2 max-w-md">
          Please upload and parse an .eml email file first to generate multi-hop entity graphs and forensic correlation models.
        </p>
        <Button variant="primary" className="mt-6" onClick={onReset}>
          Go to Ingestion
        </Button>
      </div>
    );
  }

  const { id, fileName, forensics, detection, intelligence } = analysisResult;
  const graphData = intelligence?.graph || { nodes: [], edges: [] };
  const evolution = intelligence?.infrastructure_evolution || [];

  return (
    <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-8 animate-fadeIn">
      {/* Top Banner with Sub-Navigation */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-6 rounded-2xl bg-[#111726]/90 border border-slate-800 shadow-xl backdrop-blur-md">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-1.5 font-mono">
            <span className="text-xs px-2.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-semibold">
              CASE: {id}
            </span>
            <Badge variant="info">{graphData.nodes?.length || 0} NODES</Badge>
            <Badge variant="default">{graphData.edges?.length || 0} EDGES</Badge>
            <Badge variant="dna">{detection?.attack_dna || 'ATTACK DNA'}</Badge>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold font-mono text-slate-100 uppercase tracking-tight">
            FORENSIC INTELLIGENCE & CORRELATION ENGINE
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button variant="outline" size="sm" onClick={onBackToDashboard} icon={ArrowLeft}>
            Threat Dashboard
          </Button>
          <Button variant="primary" size="sm" onClick={onViewReport} icon={Printer}>
            Export Report
          </Button>
        </div>
      </div>

      {/* Investigation Sub-Tabs Ribbon */}
      <div className="flex items-center gap-2 p-1.5 rounded-xl bg-[#111726] border border-slate-800 font-mono text-xs overflow-x-auto">
        <button
          onClick={() => setActiveTab('graph')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-bold tracking-wider whitespace-nowrap transition-all ${
            activeTab === 'graph'
              ? 'bg-cyan-500 text-slate-950 shadow-md'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>01. CAMPAIGN GRAPH (REACT FLOW)</span>
        </button>

        <button
          onClick={() => setActiveTab('timeline')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-bold tracking-wider whitespace-nowrap transition-all ${
            activeTab === 'timeline'
              ? 'bg-cyan-500 text-slate-950 shadow-md'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Calendar className="w-3.5 h-3.5" />
          <span>02. INFRASTRUCTURE TIMELINE ({evolution.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('attack_path')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-bold tracking-wider whitespace-nowrap transition-all ${
            activeTab === 'attack_path'
              ? 'bg-cyan-500 text-slate-950 shadow-md'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitMerge className="w-3.5 h-3.5" />
          <span>03. PROBABLE ATTACK PATH</span>
        </button>

        <button
          onClick={() => setActiveTab('provenance')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-bold tracking-wider whitespace-nowrap transition-all ${
            activeTab === 'provenance'
              ? 'bg-cyan-500 text-slate-950 shadow-md'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>04. EVIDENCE CHAIN</span>
        </button>

        <button
          onClick={() => setActiveTab('case_summary')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg font-bold tracking-wider whitespace-nowrap transition-all ${
            activeTab === 'case_summary'
              ? 'bg-cyan-500 text-slate-950 shadow-md'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>05. CASE SUMMARY & ACTIONS</span>
        </button>
      </div>

      {/* Tab Panels */}
      <div>
        {activeTab === 'graph' && (
          <CampaignGraphCanvas
            intelligence={intelligence}
            detection={detection}
            forensics={forensics}
            id={id}
          />
        )}

        {activeTab === 'timeline' && (
          <InfrastructureTimeline
            intelligence={intelligence}
          />
        )}

        {activeTab === 'attack_path' && (
          <ProbableAttackPath
            detection={detection}
            forensics={forensics}
            intelligence={intelligence}
          />
        )}

        {activeTab === 'provenance' && (
          <EvidenceProvenanceChain
            forensics={forensics}
            detection={detection}
            intelligence={intelligence}
          />
        )}

        {activeTab === 'case_summary' && (
          <InvestigationCaseSummary
            analysisResult={analysisResult}
            onReset={onReset}
            onViewReport={onViewReport}
          />
        )}
      </div>
    </div>
  );
}

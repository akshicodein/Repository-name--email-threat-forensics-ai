import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX, 
  AlertTriangle, 
  Dna, 
  Network, 
  ArrowLeft, 
  Copy, 
  Check, 
  FileText,
  Activity,
  Layers
} from 'lucide-react';
import { Card } from '../common/Card';
import { Button } from '../common/Button';
import { Badge } from '../common/Badge';
import { RiskGauge } from './RiskGauge';

export function HeroThreatOverview({
  analysisResult,
  onReset,
  onViewGraph,
}) {
  const [copiedDna, setCopiedDna] = React.useState(false);

  const { forensics, detection, intelligence, id, fileName, timestamp } = analysisResult;

  const riskScore = detection?.risk_score ?? (forensics?.forensics_summary?.anomaly_count ? forensics.forensics_summary.anomaly_count * 25 : 50);
  const riskLevel = detection?.risk_level ?? forensics?.forensics_summary?.risk_level ?? 'MEDIUM';
  const classification = detection?.classification ?? 'SUSPICIOUS';
  const attackDna = detection?.attack_dna ?? 'A7-F3-C9-21-88';
  const scores = detection?.scores_extended || detection?.scores || {};

  const handleCopyDna = () => {
    navigator.clipboard.writeText(attackDna);
    setCopiedDna(true);
    setTimeout(() => setCopiedDna(false), 2000);
  };

  const getThreatBadgeVariant = (lvl) => {
    switch ((lvl || '').toUpperCase()) {
      case 'CRITICAL': return 'critical';
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'default';
    }
  };

  const categoryLabels = {
    phishing: 'Phishing',
    bec: 'Business Email Compromise (BEC)',
    impersonation: 'Identity Impersonation',
    credential_theft: 'Credential Theft',
    financial_fraud: 'Financial Fraud',
    malware: 'Malware Delivery',
  };

  return (
    <div id="section-overview" className="space-y-6">
      {/* Incident Header Ribbon */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 sm:p-6 rounded-2xl bg-[#111726]/90 border border-slate-800 shadow-xl backdrop-blur-md">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-semibold">
              CASE: {id || 'CASE-2026-0881'}
            </span>
            <Badge variant={getThreatBadgeVariant(riskLevel)} dot size="sm">
              {riskLevel} THREAT
            </Badge>
            <Badge variant="dna" size="sm">
              {classification}
            </Badge>
            <span className="text-xs text-slate-400 font-mono hidden sm:inline-block">
              {fileName || 'incident_target.eml'}
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold font-mono text-slate-100 uppercase tracking-tight">
            THREAT VERDICT & FORENSIC DOSSIER
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Analyzed: {timestamp ? new Date(timestamp).toUTCString() : new Date().toUTCString()}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={onReset} icon={ArrowLeft}>
            New Email
          </Button>
          <Button variant="primary" size="sm" onClick={onViewGraph} icon={Network}>
            Threat Graph
          </Button>
        </div>
      </div>

      {/* Hero Overview Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left: Risk Gauge & Core Classification (5 cols) */}
        <Card className="lg:col-span-5 flex flex-col justify-between items-center text-center p-6 border-slate-800">
          <div className="w-full flex items-center justify-between pb-3 mb-2 border-b border-slate-800/80 text-xs font-mono text-slate-400">
            <span>CORE THREAT ASSESSMENT</span>
            <Badge variant={getThreatBadgeVariant(riskLevel)} size="xs">
              EXPLAINABLE SCORE
            </Badge>
          </div>

          <div className="my-3">
            <RiskGauge score={riskScore} level={riskLevel} size={200} />
          </div>

          <div className="w-full space-y-3 pt-2">
            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                PRIMARY VERDICT CLASSIFICATION
              </span>
              <span className="text-lg sm:text-xl font-bold font-mono text-slate-100 mt-0.5 block">
                {classification}
              </span>
            </div>

            {/* Attack DNA Badge */}
            <div className="flex items-center justify-between p-3 rounded-xl bg-violet-950/30 border border-violet-800/40 text-xs font-mono">
              <div className="flex items-center gap-2">
                <Dna className="w-4 h-4 text-violet-400 shrink-0" />
                <span className="text-slate-300">Attack DNA Fingerprint:</span>
                <span className="font-bold text-violet-300 tracking-wider">{attackDna}</span>
              </div>
              <button
                onClick={handleCopyDna}
                className="p-1 rounded hover:bg-violet-900/50 text-violet-400 transition-colors"
                title="Copy Attack DNA Identifier to clipboard"
              >
                {copiedDna ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-violet-400" />}
              </button>
            </div>
          </div>
        </Card>

        {/* Right: Multi-Category Threat Probability Distribution (7 cols) */}
        <Card className="lg:col-span-7 flex flex-col justify-between p-6 border-slate-800">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-cyan-950/50 text-cyan-400 border border-cyan-800/40">
                  <Activity className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-100 font-mono">
                    THREAT CATEGORY CONFIDENCE BREAKDOWN
                  </h3>
                  <p className="text-xs text-slate-400">
                    Calculated from technical headers, address anomalies, and NLP intent vectors
                  </p>
                </div>
              </div>
              <span className="text-xs font-mono text-cyan-400 font-bold hidden sm:inline-block">
                MEMBER 2 ENGINE
              </span>
            </div>

            <div className="space-y-3.5 my-2">
              {Object.entries(scores).map(([category, value]) => {
                const percentage = Math.round(Number(value) * 100);
                const isDominant = category.toUpperCase() === classification || (classification.includes(category.toUpperCase()));
                
                return (
                  <div key={category} className="space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className={isDominant ? 'font-bold text-cyan-300 flex items-center gap-1.5' : 'text-slate-300'}>
                        {categoryLabels[category] || category.toUpperCase()}
                        {isDominant && <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">PRIMARY</span>}
                      </span>
                      <span className={isDominant ? 'font-extrabold text-cyan-300' : 'text-slate-400'}>
                        {percentage}%
                      </span>
                    </div>

                    <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800/80">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ease-out ${
                          percentage >= 70 ? 'bg-rose-500 shadow-sm shadow-rose-500/50' :
                          percentage >= 40 ? 'bg-amber-500' :
                          percentage > 0 ? 'bg-cyan-500' : 'bg-slate-700'
                        }`}
                        style={{ width: `${Math.max(2, percentage)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Explainable AI Risk Model</span>
            <span className="text-slate-400">Deterministic Rule + NLP Persuasion Model</span>
          </div>
        </Card>
      </div>
    </div>
  );
}

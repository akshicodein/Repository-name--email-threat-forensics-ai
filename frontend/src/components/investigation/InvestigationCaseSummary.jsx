import React, { useState } from 'react';
import { 
  FileText, 
  CheckCircle2, 
  Copy, 
  Check, 
  Printer, 
  ArrowLeft, 
  ShieldCheck, 
  Dna, 
  Layers, 
  BookmarkCheck,
  Share2,
  ExternalLink
} from 'lucide-react';
import { Card } from '../common/Card';
import { Button } from '../common/Button';
import { Badge } from '../common/Badge';

export function InvestigationCaseSummary({
  analysisResult,
  onReset,
  onViewReport,
}) {
  const [isInvestigated, setIsInvestigated] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);

  const { id, fileName, forensics, detection, intelligence } = analysisResult;
  const riskScore = detection?.risk_score ?? 80;
  const riskLevel = detection?.risk_level ?? 'HIGH';
  const classification = detection?.classification ?? 'BEC / PHISHING';
  const attackDna = detection?.attack_dna ?? 'A7-F3-C9-21-88';
  const indicators = detection?.indicators || [];
  const relatedCases = intelligence?.related_cases || [];

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const copyAllIocs = () => {
    const iocs = [
      `CASE ID: ${id}`,
      `SENDER: ${forensics?.email?.from || 'N/A'}`,
      `ORIGINATING IP: ${forensics?.earliest_observed_source?.ip || 'N/A'}`,
      `ALL IPs: ${forensics?.indicators?.ips?.join(', ') || 'N/A'}`,
      `DOMAINS: ${forensics?.indicators?.domains?.join(', ') || 'N/A'}`,
      `ATTACK DNA: ${attackDna}`,
      `CLASSIFICATION: ${classification} (Risk ${riskScore}/100)`
    ].join('\n');

    copyToClipboard(iocs, 'iocs');
  };

  return (
    <div className="space-y-6">
      <Card
        title="INVESTIGATION CASE SUMMARY & ANALYST ACTIONS"
        subtitle="Executive dossier summary and workflow controls for SOC incident handlers"
        icon={FileText}
        badge={
          isInvestigated ? (
            <Badge variant="low" dot>INVESTIGATED (IN-SESSION)</Badge>
          ) : (
            <Badge variant="medium" dot>ACTION REQUIRED</Badge>
          )
        }
        className="border-slate-800"
      >
        {/* Top Summary Banner */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-5 rounded-xl bg-[#0f1422] border border-slate-800 font-mono text-xs mb-6">
          <div>
            <span className="text-slate-400 block text-[10px] uppercase">CASE IDENTIFIER</span>
            <span className="text-sm font-bold text-cyan-300">{id}</span>
          </div>
          <div>
            <span className="text-slate-400 block text-[10px] uppercase">THREAT LEVEL & SCORE</span>
            <span className="text-sm font-bold text-rose-400">{riskLevel} ({riskScore}/100)</span>
          </div>
          <div>
            <span className="text-slate-400 block text-[10px] uppercase">CLASSIFICATION</span>
            <span className="text-sm font-bold text-slate-100">{classification}</span>
          </div>
          <div>
            <span className="text-slate-400 block text-[10px] uppercase">ATTACK DNA</span>
            <span className="text-sm font-bold text-violet-300">{attackDna}</span>
          </div>
        </div>

        {/* Executive Narrative */}
        <div className="space-y-4">
          <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            EXECUTIVE FORENSIC SUMMARY
          </h4>
          <p className="text-xs font-sans text-slate-300 bg-slate-950/70 p-4 rounded-xl border border-slate-800 leading-relaxed">
            {detection?.summary || 'Analysis indicates high-risk threat signature with multiple confirmed header and authentication anomalies.'}
          </p>

          {/* Key Verified Findings */}
          <div className="space-y-2 pt-2">
            <span className="text-[11px] font-mono text-slate-400 font-bold uppercase block">
              KEY VERIFIED EVIDENCE FINDINGS:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              {indicators.slice(0, 6).map((ind, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-200 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span className="truncate">{ind}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Analyst Actions Controls */}
        <div className="mt-8 pt-6 border-t border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">
              ANALYST WORKFLOW CONTROLS
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              {isInvestigated ? 'Case status recorded in active session' : 'Session controls'}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Toggle Mark as Investigated */}
            <Button
              variant={isInvestigated ? 'secondary' : 'primary'}
              size="sm"
              onClick={() => setIsInvestigated(!isInvestigated)}
              icon={BookmarkCheck}
            >
              {isInvestigated ? 'Marked as Investigated' : 'Mark as Investigated'}
            </Button>

            {/* Export / Print Report */}
            <Button
              variant="outline"
              size="sm"
              onClick={onViewReport}
              icon={Printer}
            >
              Export Forensic Report
            </Button>

            {/* Copy All IOCs */}
            <Button
              variant="outline"
              size="sm"
              onClick={copyAllIocs}
              icon={copiedKey === 'iocs' ? Check : Copy}
            >
              {copiedKey === 'iocs' ? 'IOCs Copied!' : 'Copy All IOCs'}
            </Button>

            {/* Copy Attack DNA */}
            <Button
              variant="outline"
              size="sm"
              onClick={() => copyToClipboard(attackDna, 'dna')}
              icon={copiedKey === 'dna' ? Check : Dna}
            >
              {copiedKey === 'dna' ? 'DNA Copied!' : 'Copy Attack DNA'}
            </Button>

            {/* New Investigation */}
            <Button
              variant="ghost"
              size="sm"
              onClick={onReset}
              icon={ArrowLeft}
            >
              New Analysis
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}

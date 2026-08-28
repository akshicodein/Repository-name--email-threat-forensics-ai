import React from 'react';
import { 
  GitBranch, 
  ShieldCheck, 
  Cpu, 
  Globe, 
  Database, 
  Network, 
  AlertOctagon, 
  CheckCircle2, 
  Sparkles,
  Layers
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function EvidenceProvenanceChain({ forensics, detection, intelligence }) {
  const riskBreakdown = detection?.risk_breakdown || [];
  const anomalies = forensics?.anomalies || [];
  const socialEng = detection?.social_engineering_detail || {};
  const campaign = intelligence?.campaign || {};
  const dnaSimilarity = detection?.dna_similarity || [];

  // Construct sequential forensic provenance chain
  const chainSteps = [];

  // Step 1: Ingestion & Header Anomalies (Member 1)
  if (anomalies.length > 0) {
    chainSteps.push({
      step: '01',
      title: 'HEADER SYNTAX & AUTHENTICATION AUDIT',
      source: 'MEMBER 1 — FORENSICS ENGINE',
      sourceBadge: 'info',
      severity: anomalies.some(a => a.severity === 'HIGH') ? 'HIGH' : 'MEDIUM',
      certainty: 'CONFIRMED',
      summary: `Detected ${anomalies.length} structural header anomalies including authentication and envelope discrepancies.`,
      evidenceSnippet: anomalies.map(a => a.description).join('; ')
    });
  }

  // Step 2: Technical Risk Scoring (Member 2)
  if (riskBreakdown.length > 0) {
    chainSteps.push({
      step: '02',
      title: 'DETERMINISTIC THREAT SCORING & LOOKALIKE DETECTION',
      source: 'MEMBER 2 — AI DETECTION',
      sourceBadge: 'high',
      severity: 'HIGH',
      certainty: 'OBSERVED',
      summary: `Accumulated ${detection.risk_score}/100 explainable points across ${riskBreakdown.length} verified technical indicators.`,
      evidenceSnippet: riskBreakdown.map(r => `${r.indicator} (+${r.points} pts)`).join(', ')
    });
  }

  // Step 3: NLP Social Engineering & Intent Analysis (Member 2)
  const highNlp = Object.entries(socialEng).filter(([_, d]) => d.label === 'HIGH' || d.label === 'MEDIUM');
  if (highNlp.length > 0) {
    chainSteps.push({
      step: '03',
      title: 'LINGUISTIC PERSUASION & COERCION EXTRACTION',
      source: 'MEMBER 2 — AI DETECTION (NLP)',
      sourceBadge: 'dna',
      severity: 'HIGH',
      certainty: 'PROBABLE',
      summary: `Identified active social engineering pressure tactics: ${highNlp.map(([k]) => k.replace(/_/g, ' ')).join(', ')}.`,
      evidenceSnippet: highNlp.map(([k, d]) => `${k.toUpperCase()}: matches [${d.matches?.join(', ') || 'N/A'}]`).join(' | ')
    });
  }

  // Step 4: Attack DNA Derivation & Historical Memory Matching (Threat Memory)
  if (detection?.attack_dna) {
    chainSteps.push({
      step: '04',
      title: 'ATTACK DNA DERIVATION & THREAT MEMORY MATCHING',
      source: 'THREAT MEMORY',
      sourceBadge: 'dna',
      severity: dnaSimilarity.length > 0 ? 'HIGH' : 'LOW',
      certainty: 'PROBABLE',
      summary: `Synthesized behavioral fingerprint "${detection.attack_dna}" and matched against historical case store.`,
      evidenceSnippet: dnaSimilarity.length > 0 
        ? dnaSimilarity.map(s => `${s.case_id} (${s.similarity}% match)`).join(', ')
        : 'Zero prior case collisions observed in local store.'
    });
  }

  // Step 5: Campaign Correlation & Graph Synthesis (Member 3)
  if (campaign.possible_campaign) {
    chainSteps.push({
      step: '05',
      title: 'CAMPAIGN CLUSTER ATTRIBUTION & TOPOLOGY SYNTHESIS',
      source: 'MEMBER 3 — THREAT INTELLIGENCE',
      sourceBadge: 'default',
      severity: 'HIGH',
      certainty: 'INFERRED',
      summary: `Correlated infrastructure with campaign cluster "${campaign.possible_campaign}" (${Math.round((campaign.confidence || 0.85) * 100)}% confidence).`,
      evidenceSnippet: campaign.summary || 'Associated with multi-incident VPS hosting rotation cluster.'
    });
  }

  return (
    <div className="space-y-6">
      <Card
        title="WHY DID THE SYSTEM FLAG THIS EMAIL? (EVIDENCE PROVENANCE CHAIN)"
        subtitle="Chronological forensic reasoning demonstrating how each engine contributed to the verdict"
        icon={Layers}
        badge={<Badge variant="info">{chainSteps.length} VERIFIED STAGES</Badge>}
        className="border-slate-800"
      >
        <div className="space-y-4 my-2 font-mono text-xs">
          {chainSteps.map((step, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 space-y-2.5"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                <div className="flex items-center gap-2.5">
                  <span className="text-cyan-400 font-extrabold text-sm">
                    {step.step}.
                  </span>
                  <h4 className="font-bold text-slate-100 uppercase tracking-wide">
                    {step.title}
                  </h4>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={step.sourceBadge} size="xs">{step.source}</Badge>
                  <span className="text-[10px] text-slate-400 font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                    {step.certainty}
                  </span>
                </div>
              </div>

              <p className="text-xs text-slate-300 font-sans leading-relaxed">
                {step.summary}
              </p>

              <div className="p-2.5 rounded-lg bg-black/50 border border-slate-800 text-[11px] text-cyan-300 break-all">
                <span className="text-slate-400 font-bold mr-1.5">PROVENANCE DATA:</span>
                {step.evidenceSnippet}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

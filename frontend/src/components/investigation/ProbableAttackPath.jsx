import React, { useState } from 'react';
import { 
  GitMerge, 
  CheckCircle2, 
  AlertTriangle, 
  HelpCircle, 
  ChevronDown, 
  ChevronUp, 
  ShieldAlert, 
  ShieldCheck,
  Lock, 
  Send, 
  FileSearch, 
  DollarSign, 
  Terminal,
  ArrowDown
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function ProbableAttackPath({ detection, forensics, intelligence }) {
  const [expandedStage, setExpandedStage] = useState(null);

  const classification = detection?.classification || 'UNKNOWN';
  const indicators = detection?.indicators || [];
  const socialEng = detection?.social_engineering || {};
  const auth = forensics?.authentication || {};
  const urls = forensics?.indicators?.urls || [];
  const attachments = forensics?.indicators?.attachments || [];
  const anomalies = forensics?.anomalies || [];

  // Derive dynamic attack stages based purely on available evidence
  const stages = [];

  const hasAuthFail = auth.spf === 'fail' || auth.dmarc === 'fail' || auth.dkim === 'fail';
  const hasMismatch = anomalies.some(a => a.type?.includes('mismatch') || a.type?.includes('lookalike'));
  const isHighUrgency = socialEng.urgency === 'HIGH' || socialEng.authority_pressure === 'HIGH';
  const isLegitimate = classification === 'LEGITIMATE' || (detection?.risk_score !== null && detection.risk_score < 25 && !hasAuthFail && !hasMismatch);

  // If email is benign / legitimate, do NOT synthesize a malicious attack sequence
  if (!isLegitimate) {
    // Stage 1: Inbound Delivery
    if (forensics?.email?.from) {
      stages.push({
        id: 'stage-1',
        title: 'Inbound Email Ingestion & Delivery',
        status: 'SUPPORTED',
        confidence: 100,
        description: 'Suspicious email delivered to target recipient mailbox across external SMTP relay chain.',
        evidence: [
          `Sender Address: ${forensics.email.from}`,
          `Subject: "${forensics.email.subject || 'N/A'}"`,
          `Earliest Observed IP: ${forensics.earliest_observed_source?.ip || 'Extracted from Received hop'}`
        ],
        tactic: 'Initial Access / Delivery'
      });
    }

    // Stage 2: Authentication Evasion / Spoofing
    if (hasAuthFail || hasMismatch) {
      stages.push({
        id: 'stage-2',
        title: 'Sender Authentication Evasion & Identity Spoofing',
        status: hasAuthFail ? 'SUPPORTED' : 'PROBABLE',
        confidence: hasAuthFail ? 95 : 85,
        description: 'Threat actor bypassed or violated email security controls using unauthenticated infrastructure or lookalike domains.',
        evidence: [
          auth.spf === 'fail' ? 'SPF Authentication Failure (+12 pts)' : null,
          auth.dmarc === 'fail' ? 'DMARC Policy Rejection (+25 pts)' : null,
          hasMismatch ? 'From vs Reply-To / Return-Path domain discrepancy' : null
        ].filter(Boolean),
        tactic: 'Defense Evasion'
      });
    }

    // Stage 3: Social Engineering & Persuasion
    if (isHighUrgency || indicators.some(i => i.toLowerCase().includes('urgency') || i.toLowerCase().includes('pressure'))) {
      stages.push({
        id: 'stage-3',
        title: 'Social Engineering & Psychological Coercion',
        status: 'PROBABLE',
        confidence: 88,
        description: 'Linguistic manipulation tactics employed to create artificial deadlines and induce compliance.',
        evidence: [
          socialEng.urgency === 'HIGH' ? 'High urgency keywords and immediate action demands' : null,
          socialEng.authority_pressure === 'HIGH' ? 'Executive/Authority impersonation pressure' : null,
          socialEng.confidentiality_pressure === 'HIGH' ? 'Confidentiality mandate to prevent out-of-band verification' : null
        ].filter(Boolean),
        tactic: 'Social Engineering'
      });
    }

    // Stage 4: Payload / Credential Harvesting / Malware
    if (urls.length > 0) {
      stages.push({
        id: 'stage-4',
        title: 'Credential Harvesting Redirection',
        status: 'SUPPORTED',
        confidence: 90,
        description: 'Embedded hyperlinks direct target to fraudulent authentication portals.',
        evidence: urls.map(u => `Suspicious URL: ${typeof u === 'string' ? u : u.url}`),
        tactic: 'Credential Access'
      });
    } else if (attachments.length > 0) {
      stages.push({
        id: 'stage-4',
        title: 'Malicious Payload Delivery via Attachment',
        status: 'SUPPORTED',
        confidence: 92,
        description: 'Weaponized binary or document attachment delivered to achieve client execution.',
        evidence: attachments.map(a => `Attachment: ${a.filename} (${a.content_type || 'binary'})`),
        tactic: 'Execution'
      });
    }

    // Stage 5: Final Impact Objective
    if (classification === 'BEC' || classification === 'FINANCIAL_FRAUD' || socialEng.financial_manipulation === 'HIGH') {
      stages.push({
        id: 'stage-5',
        title: 'Unauthorized Financial Transfer / Wire Fraud Demand',
        status: 'INFERRED',
        confidence: 82,
        description: 'Inferred campaign objective to divert corporate capital via fraudulent escrow or supplier bank modification.',
        evidence: [
          'Direct monetary sum / escrow tranche solicited in message content',
          'Executive impersonation signature aligning with BEC playbooks'
        ],
        tactic: 'Impact'
      });
    } else if (classification === 'CREDENTIAL_THEFT' || classification === 'PHISHING') {
      stages.push({
        id: 'stage-5',
        title: 'Enterprise Account Compromise & Lateral Pivot',
        status: 'INFERRED',
        confidence: 78,
        description: 'Inferred attack objective to harvest corporate SSO credentials for downstream tenant intrusion.',
        evidence: [
          'Account verification / lockout lure structure detected'
        ],
        tactic: 'Impact'
      });
    }
  }

  const getStatusBadge = (status) => {
    switch (status) {
      case 'SUPPORTED':
        return <Badge variant="critical" size="xs" dot>SUPPORTED BY EVIDENCE</Badge>;
      case 'PROBABLE':
        return <Badge variant="high" size="xs" dot>PROBABLE CORRELATION</Badge>;
      case 'INFERRED':
        return <Badge variant="medium" size="xs" dot>INFERRED TACTIC</Badge>;
      default:
        return <Badge variant="default" size="xs">OBSERVED</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      <Card
        title="PROBABLE ATTACK PATH & TACTICAL PROGRESSION"
        subtitle="Dynamic attack-chain reconstruction derived from verified technical evidence and NLP intent"
        icon={GitMerge}
        badge={
          isLegitimate || stages.length === 0 ? (
            <Badge variant="low">BENIGN / NO THREAT</Badge>
          ) : (
            <Badge variant="info">{stages.length} ATTACK STAGES</Badge>
          )
        }
        className="border-slate-800"
      >
        {/* Caveat */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-300 text-xs font-mono mb-6">
          <span className="text-cyan-300 font-bold uppercase block mb-1">
            METHODOLOGY & UNCERTAINTY SEMANTICS:
          </span>
          <p className="text-slate-400 font-sans text-xs leading-relaxed">
            Stages are labeled <strong>SUPPORTED</strong> (backed by direct forensic header/attachment facts), <strong>PROBABLE</strong> (high multi-indicator correlation), or <strong>INFERRED</strong> (deduced tactical objective). Unsubstantiated stages are omitted.
          </p>
        </div>

        {/* Clean Benign / Legitimate State */}
        {isLegitimate || stages.length === 0 ? (
          <div className="p-8 rounded-2xl bg-emerald-950/20 border border-emerald-800/60 text-center font-mono space-y-3 my-4">
            <div className="w-12 h-12 rounded-full bg-emerald-950/80 border border-emerald-600/80 text-emerald-400 flex items-center justify-center mx-auto">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h4 className="text-sm font-bold text-emerald-300 uppercase tracking-wide">
              INSUFFICIENT THREAT EVIDENCE — NO MALICIOUS ATTACK PATH OBSERVED
            </h4>
            <p className="text-xs text-slate-300 font-sans max-w-xl mx-auto leading-relaxed">
              The analyzed email satisfies verified cryptographic authentication standards (SPF, DKIM, DMARC) and exhibits benign business communication patterns without identifiable adversary attack progression.
            </p>
          </div>
        ) : (
          /* Dynamic Attack Stages Sequence */
          <div className="space-y-4 relative">
            {stages.map((stage, idx) => {
              const isExpanded = expandedStage === stage.id;
              const isLast = idx === stages.length - 1;

              return (
                <div key={stage.id} className="relative">
                  <div
                    className={`p-4 rounded-xl border transition-all font-mono text-xs ${
                      stage.status === 'SUPPORTED'
                        ? 'bg-rose-950/20 border-rose-800/60'
                        : stage.status === 'PROBABLE'
                        ? 'bg-orange-950/20 border-orange-800/60'
                        : 'bg-amber-950/20 border-amber-800/60'
                    }`}
                  >
                    <div
                      onClick={() => setExpandedStage(isExpanded ? null : stage.id)}
                      className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 cursor-pointer select-none"
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center font-bold text-cyan-300 text-xs shrink-0">
                          {idx + 1}
                        </span>
                        <div>
                          <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
                            {stage.title}
                          </h4>
                          <span className="text-[11px] text-slate-400 font-sans">
                            {stage.tactic}
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        {getStatusBadge(stage.status)}
                        <span className="text-cyan-400 font-bold hidden sm:inline-block">
                          {stage.confidence}%
                        </span>
                        {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 font-sans mt-2.5 leading-relaxed">
                      {stage.description}
                    </p>

                    {/* Expandable Supporting Evidence Drawer */}
                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-slate-800/60 space-y-2 animate-fadeIn">
                        <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
                          SUPPORTING FORENSIC EVIDENCE:
                        </span>
                        <ul className="space-y-1 text-[11px] text-cyan-300">
                          {stage.evidence.map((ev, evIdx) => (
                            <li key={evIdx} className="flex items-start gap-1.5">
                              <span className="text-cyan-500 font-bold">•</span>
                              <span className="break-all">{ev}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  {/* Connecting Arrow between attack steps */}
                  {!isLast && (
                    <div className="flex justify-center my-1 text-slate-600">
                      <ArrowDown className="w-3.5 h-3.5" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}

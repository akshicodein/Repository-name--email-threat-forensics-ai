import React from 'react';
import { 
  HelpCircle, 
  AlertOctagon, 
  AlertTriangle, 
  Info, 
  CheckCircle2, 
  Sparkles, 
  MessageSquare, 
  KeyRound, 
  DollarSign, 
  Clock, 
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function WhySuspiciousEvidence({ detection, forensics }) {
  const riskBreakdown = detection?.risk_breakdown || [];
  const anomalies = forensics?.anomalies || [];
  const socialEngineering = detection?.social_engineering_detail || {};
  const narrativeSummary = detection?.summary || 'Analysis complete.';

  // Build unified evidence items list
  const evidenceItems = [];

  // Add technical score breakdown items
  riskBreakdown.forEach((item, idx) => {
    evidenceItems.push({
      id: `tech-${idx}`,
      type: 'TECHNICAL_INDICATOR',
      title: item.indicator ? item.indicator.replace(/_/g, ' ') : 'Technical Indicator',
      severity: item.points >= 20 ? 'HIGH' : item.points >= 10 ? 'MEDIUM' : 'LOW',
      points: `+${item.points} pts`,
      explanation: item.detail || 'Technical forensic anomaly detected in email headers or structure.',
      evidenceField: item.indicator || 'Not available',
      source: 'Member 2 Technical Scoring'
    });
  });

  // Add Member 1 Header Anomalies if not duplicated
  anomalies.forEach((anom, idx) => {
    const isAlreadyPresent = evidenceItems.some(
      (e) => e.title.toLowerCase() === (anom.type || '').replace(/_/g, ' ').toLowerCase()
    );
    if (!isAlreadyPresent) {
      evidenceItems.push({
        id: `anom-${idx}`,
        type: 'HEADER_ANOMALY',
        title: anom.type ? anom.type.replace(/_/g, ' ') : 'Header Anomaly',
        severity: anom.severity || 'MEDIUM',
        points: null,
        explanation: anom.description || 'Discrepancy detected during RFC 822 header parsing.',
        evidenceField: anom.evidence ? JSON.stringify(anom.evidence) : 'Not available',
        source: 'Member 1 Forensics Engine'
      });
    }
  });

  // Add Social Engineering Matched Phrases
  Object.entries(socialEngineering).forEach(([dim, detail], idx) => {
    if (detail.label === 'HIGH' || detail.label === 'MEDIUM') {
      evidenceItems.push({
        id: `nlp-${idx}`,
        type: 'LINGUISTIC_PERSUASION',
        title: `${dim.replace(/_/g, ' ')} (${detail.label} Severity)`,
        severity: detail.label,
        points: `Raw Score: ${Math.round((detail.raw_score || 0) * 100)}%`,
        explanation: `Social engineering pressure tactic detected in email body/subject.`,
        evidenceField: detail.matches && detail.matches.length > 0 ? `Matched keywords: "${detail.matches.join('", "')}"` : 'Not available',
        source: 'Member 2 NLP Threat Engine'
      });
    }
  });

  const getSeverityBadge = (sev) => {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL': return <Badge variant="critical" dot>CRITICAL</Badge>;
      case 'HIGH': return <Badge variant="high" dot>HIGH</Badge>;
      case 'MEDIUM': return <Badge variant="medium" dot>MEDIUM</Badge>;
      case 'LOW': return <Badge variant="low">LOW</Badge>;
      default: return <Badge variant="default">INFO</Badge>;
    }
  };

  return (
    <div id="section-why" className="space-y-6">
      <Card
        title="WHY IS THIS SUSPICIOUS?"
        subtitle="Transparent, explainable evidence dossier linking every threat finding to verified indicators"
        icon={HelpCircle}
        badge={<Badge variant="info">EVIDENCE DOSSIER</Badge>}
        className="border-slate-800"
      >
        {/* Narrative Finding Banner */}
        <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/40 text-slate-200 text-sm font-sans leading-relaxed mb-6 flex items-start gap-3">
          <Sparkles className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold text-cyan-300 font-mono block text-xs uppercase mb-1">
              AUTOMATED FORENSIC SUMMARY:
            </span>
            <p>{narrativeSummary}</p>
          </div>
        </div>

        {/* Evidence Items Grid */}
        <div className="space-y-3.5">
          {evidenceItems.length > 0 ? (
            evidenceItems.map((item) => (
              <div
                key={item.id}
                className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 hover:border-slate-700 transition-all space-y-2.5"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    {getSeverityBadge(item.severity)}
                    <h4 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wide">
                      {item.title}
                    </h4>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-xs">
                    {item.points && (
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-amber-300 font-bold">
                        {item.points}
                      </span>
                    )}
                    <span className="text-[11px] text-slate-400">{item.source}</span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 font-sans leading-relaxed">
                  {item.explanation}
                </p>

                {/* Supporting Field / Evidence Snippet */}
                <div className="pt-2 border-t border-slate-800/60 flex items-start gap-2 text-xs font-mono">
                  <span className="text-slate-400 shrink-0">EVIDENCE:</span>
                  <span className="text-cyan-300 font-medium break-all bg-black/40 px-2 py-0.5 rounded border border-slate-800/80">
                    {item.evidenceField}
                  </span>
                </div>
              </div>
            ))
          ) : (
            <div className="p-6 rounded-xl bg-emerald-950/20 border border-emerald-800/40 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
              <p className="text-sm font-bold font-mono text-emerald-300">
                NO SUSPICIOUS ANOMALIES IDENTIFIED
              </p>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                All authentication checks passed and no social engineering urgency signals were observed.
              </p>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

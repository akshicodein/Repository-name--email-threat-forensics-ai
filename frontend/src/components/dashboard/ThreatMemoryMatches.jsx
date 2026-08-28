import React from 'react';
import { 
  Database, 
  Dna, 
  GitCompare, 
  AlertTriangle, 
  CheckCircle2, 
  ExternalLink, 
  Share2,
  Calendar,
  Layers
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function ThreatMemoryMatches({ detection, intelligence }) {
  const dnaSimilarity = detection?.dna_similarity || [];
  const relatedCases = intelligence?.related_cases || [];
  const campaign = intelligence?.campaign || {};

  // Combine Member 2 similarity matches and Member 3 related cases
  const allMatches = [];

  dnaSimilarity.forEach((match) => {
    allMatches.push({
      caseId: match.case_id,
      similarity: match.similarity,
      threatType: match.classification || 'BEC / PHISHING',
      attackDna: match.attack_dna || 'Not recorded',
      note: match.note || 'High cosine similarity across feature vector.',
      sharedIocs: [],
      source: 'Member 2 Attack DNA Memory'
    });
  });

  relatedCases.forEach((rc) => {
    const existing = allMatches.find((m) => m.caseId === rc.case_id);
    if (existing) {
      existing.sharedIocs = rc.shared_indicators || [];
      existing.relationship = rc.relationship;
    } else {
      allMatches.push({
        caseId: rc.case_id,
        similarity: rc.similarity || null,
        threatType: 'HISTORICAL INCIDENT',
        attackDna: 'N/A',
        note: rc.relationship || 'Shared infrastructure IOCs discovered in threat graph.',
        sharedIocs: rc.shared_indicators || [],
        source: 'Member 3 Graph Correlator'
      });
    }
  });

  return (
    <div id="section-threat-memory" className="space-y-6">
      <Card
        title="THREAT MEMORY & HISTORICAL CAMPAIGN MATCHES"
        subtitle="Cosine similarity matching against historical case store and shared infrastructure graph"
        icon={Database}
        badge={<Badge variant="dna">{allMatches.length} CORRELATED CASES</Badge>}
        className="border-slate-800"
      >
        {/* Campaign Banner if present */}
        {campaign.possible_campaign && (
          <div className="p-4 rounded-xl bg-orange-950/20 border border-orange-800/40 space-y-2 mb-6 font-mono text-xs">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-orange-400 font-bold uppercase tracking-wider">
                  ACTIVE CAMPAIGN CLUSTER:
                </span>
                <span className="text-slate-100 font-extrabold text-sm">
                  {campaign.possible_campaign}
                </span>
              </div>
              <Badge variant="high">
                {Math.round((campaign.confidence || 0) * 100)}% CONFIDENCE
              </Badge>
            </div>
            <p className="text-slate-300 font-sans text-xs leading-relaxed">
              {campaign.summary}
            </p>
          </div>
        )}

        {/* Matches Grid */}
        {allMatches.length > 0 ? (
          <div className="space-y-3 font-mono text-xs">
            {allMatches.map((item, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 hover:border-violet-800/60 transition-all space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                  <div className="flex items-center gap-2.5">
                    <span className="text-base font-bold text-violet-300">{item.caseId}</span>
                    <Badge variant="default" size="xs">{item.threatType}</Badge>
                  </div>
                  {item.similarity !== null && (
                    <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
                      <GitCompare className="w-3.5 h-3.5" />
                      <span>{item.similarity}% VECTOR SIMILARITY</span>
                    </div>
                  )}
                </div>

                <p className="text-slate-300 font-sans text-xs leading-relaxed">
                  {item.note}
                </p>

                {/* Footer metadata */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-[11px] text-slate-400">
                  <div className="flex items-center gap-2">
                    {item.attackDna !== 'N/A' && (
                      <span>DNA: <strong className="text-violet-300">{item.attackDna}</strong></span>
                    )}
                    {item.sharedIocs && item.sharedIocs.length > 0 && (
                      <span>• Shared IOCs: <strong className="text-cyan-300">{item.sharedIocs.join(', ')}</strong></span>
                    )}
                  </div>
                  <span className="text-slate-400">{item.source}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-8 rounded-xl bg-slate-900/40 border border-slate-800 text-center font-mono text-xs text-slate-400 space-y-2">
            <CheckCircle2 className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="font-bold text-slate-300">
              NO HISTORICAL MATCHES AVAILABLE
            </p>
            <p className="text-[11px] text-slate-400 max-w-md mx-auto">
              This incident does not exhibit sufficient Attack DNA or IOC overlap with previously stored cases in the Threat Memory database.
            </p>
          </div>
        )}
      </Card>
    </div>
  );
}

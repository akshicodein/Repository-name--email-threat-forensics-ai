import React from 'react';
import { 
  Dna, 
  Layers, 
  Info, 
  Cpu, 
  Hash, 
  Sparkles, 
  Activity,
  CheckCircle2
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function AttackDnaExplainer({ detection }) {
  const attackDna = detection?.attack_dna || 'A7-F3-C9-21-88';
  const dnaBreakdown = detection?.attack_dna_breakdown || [];
  const features = detection?.features || {};

  const defaultCategories = [
    { byte: attackDna.split('-')[0] || 'A7', category: 'HEADER_AUTH', interpretation: 'SPF/DKIM/DMARC authentication anomaly signature' },
    { byte: attackDna.split('-')[1] || 'F3', category: 'DOMAIN_URL', interpretation: 'Domain structure, lookalike brand deception & URL traits' },
    { byte: attackDna.split('-')[2] || 'C9', category: 'PRESSURE_LANGUAGE', interpretation: 'Urgency, fear, artificial deadlines & executive coercion' },
    { byte: attackDna.split('-')[3] || '21', category: 'SOCIAL_ENG', interpretation: 'Credential solicitation, verification lures & CTAs' },
    { byte: attackDna.split('-')[4] || '88', category: 'INTENT_PROFILE', interpretation: 'Financial manipulation, wire requests & payload delivery' },
  ];

  const breakdownToRender = dnaBreakdown.length > 0 ? dnaBreakdown : defaultCategories;

  return (
    <div id="section-attack-dna" className="space-y-6">
      <Card
        title="ATTACK DNA FINGERPRINT & BEHAVIORAL PROFILE"
        subtitle="Behavioral fingerprint quantized from normalized feature vector representations"
        icon={Dna}
        badge={<Badge variant="dna">{attackDna}</Badge>}
        className="border-slate-800"
      >
        {/* Definition & Safe Attribution Notice */}
        <div className="p-3.5 rounded-xl bg-violet-950/20 border border-violet-800/40 text-violet-300 text-xs font-mono flex items-start gap-3 mb-6">
          <Info className="w-4 h-4 shrink-0 text-violet-400 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold uppercase tracking-wider block">
              ATTACK DNA DEFINITION:
            </span>
            <p className="text-slate-300 font-sans leading-relaxed">
              Attack DNA is a <strong>behavioral fingerprint derived from normalized technical and linguistic feature vectors</strong>. It allows automated clustering and correlation across campaigns. It is a mathematical behavioral signature, not a confirmed biological or personal attacker identity.
            </p>
          </div>
        </div>

        {/* Feature Segment Visual Blocks */}
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 mb-8">
          {breakdownToRender.map((item, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-900/90 border border-violet-800/50 flex flex-col items-center justify-between text-center space-y-2 font-mono shadow-md shadow-violet-950/20"
            >
              <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
                SEGMENT #{idx + 1}
              </span>
              <span className="text-3xl font-black text-violet-300 font-mono tracking-widest bg-violet-950/60 px-3 py-1 rounded-lg border border-violet-700/60">
                {item.byte}
              </span>
              <span className="text-[11px] font-semibold text-cyan-300 uppercase">
                {item.category.replace('_', ' ')}
              </span>
            </div>
          ))}
        </div>

        {/* Detailed Semantic Table */}
        <div className="space-y-3">
          <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            FEATURE SEGMENT INTERPRETATION
          </h4>

          <div className="space-y-2.5 font-mono text-xs">
            {breakdownToRender.map((item, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-[#0f1422] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-violet-950 text-violet-300 font-bold text-xs border border-violet-800 shrink-0">
                    {item.byte}
                  </span>
                  <div>
                    <span className="font-bold text-slate-100 uppercase tracking-wide">
                      {item.category.replace('_', ' ')}
                    </span>
                    <p className="text-slate-400 font-sans text-xs mt-0.5">
                      {item.interpretation}
                    </p>
                  </div>
                </div>

                {item.score !== undefined && (
                  <div className="text-right shrink-0">
                    <span className="text-[11px] text-slate-400 block">VECTOR VALUE</span>
                    <span className="text-xs font-bold text-violet-300">
                      {Math.round(item.score * 100)}%
                    </span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Normalized Feature Vector Grid */}
        {Object.keys(features).length > 0 && (
          <div className="mt-8 pt-6 border-t border-slate-800">
            <h4 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-3">
              NORMALIZED FEATURE MATRIX
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 text-[11px] font-mono">
              {Object.entries(features).map(([feat, val]) => (
                <div key={feat} className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400 truncate max-w-[120px]">{feat.replace(/_/g, ' ')}</span>
                  <span className={`font-bold ${Number(val) > 0.5 ? 'text-rose-400' : 'text-slate-400'}`}>
                    {Number(val).toFixed(2)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

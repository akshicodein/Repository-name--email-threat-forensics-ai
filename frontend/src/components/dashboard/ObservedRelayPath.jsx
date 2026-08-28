import React from 'react';
import { 
  GitBranch, 
  Server, 
  ArrowDown, 
  ShieldAlert, 
  Clock, 
  Globe, 
  Info,
  CheckCircle2
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function ObservedRelayPath({ forensics, intelligence }) {
  const receivedChain = forensics?.headers?.received_chain || [];
  const earliestSource = forensics?.earliest_observed_source;
  const ipIntelList = intelligence?.ip_intelligence || [];

  return (
    <div id="section-relay" className="space-y-6">
      <Card
        title="OBSERVED RELAY PATH (RECEIVED HEADER FORENSICS)"
        subtitle="Chronological multi-hop reconstruction from earliest observed source to destination mail exchanger"
        icon={GitBranch}
        badge={<Badge variant="info">{receivedChain.length} HOPS RECONSTRUCTED</Badge>}
        className="border-slate-800"
      >
        {/* Forensic Attribution Warning Notice */}
        <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-800/40 text-amber-300 text-xs font-mono flex items-start gap-2.5 mb-6">
          <Info className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
          <div>
            <span className="font-bold uppercase tracking-wider block">
              FORENSIC ATTRIBUTION CAVEAT:
            </span>
            <span>
              Hop 1 represents the <strong>earliest reliable observed network source</strong>. It may represent a VPN endpoint, cloud VPS, proxy node, Tor relay, or compromised relay host rather than a perpetrator’s true physical machine.
            </span>
          </div>
        </div>

        {/* Chronological Flow Tree */}
        <div className="space-y-4 relative">
          {receivedChain.length > 0 ? (
            receivedChain.map((hop, idx) => {
              const isEarliest = idx === 0;
              const isFinal = idx === receivedChain.length - 1;
              const ipIntel = hop.ip ? ipIntelList.find((i) => i.ip === hop.ip) : null;

              return (
                <div key={idx} className="relative">
                  <div
                    className={`p-4 rounded-xl border transition-all ${
                      isEarliest
                        ? 'bg-gradient-to-r from-rose-950/30 via-slate-900/80 to-slate-900/80 border-rose-700/60 shadow-lg shadow-rose-950/20'
                        : isFinal
                        ? 'bg-slate-900/80 border-emerald-800/60'
                        : 'bg-slate-900/60 border-slate-800'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 mb-3 border-b border-slate-800/60 font-mono text-xs">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                            isEarliest
                              ? 'bg-rose-950 border border-rose-700 text-rose-300'
                              : isFinal
                              ? 'bg-emerald-950 border border-emerald-700 text-emerald-300'
                              : 'bg-cyan-950 border border-cyan-800 text-cyan-300'
                          }`}
                        >
                          HOP #{hop.hop}
                        </span>
                        <span className="font-bold text-slate-100 uppercase tracking-wide">
                          {isEarliest
                            ? 'OBSERVED SOURCE INFRASTRUCTURE'
                            : isFinal
                            ? 'RECIPIENT INGESTION GATEWAY'
                            : 'INTERMEDIATE MAIL RELAY'}
                        </span>
                      </div>

                      {hop.timestamp && (
                        <div className="flex items-center gap-1.5 text-slate-400 text-[11px]">
                          <Clock className="w-3 h-3 text-slate-500" />
                          <span>{hop.timestamp}</span>
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
                      {/* From Host */}
                      <div>
                        <span className="text-[10px] text-slate-500 block uppercase">FROM HOST</span>
                        <span className="text-slate-200 font-semibold break-all">
                          {hop.from_host || 'Unknown / Not declared'}
                        </span>
                      </div>

                      {/* Observed IP */}
                      <div>
                        <span className="text-[10px] text-slate-500 block uppercase">OBSERVED IP</span>
                        <span className={hop.ip ? 'text-cyan-300 font-bold' : 'text-slate-500 italic'}>
                          {hop.ip || 'No IP in header'}
                        </span>
                        {ipIntel && (
                          <span className="block text-[11px] text-slate-400">
                            {ipIntel.city}, {ipIntel.country} ({ipIntel.asn || 'ASN N/A'})
                          </span>
                        )}
                      </div>

                      {/* By Host */}
                      <div>
                        <span className="text-[10px] text-slate-500 block uppercase">RECEIVED BY HOST</span>
                        <span className="text-slate-300 break-all">
                          {hop.by_host || 'Unknown'}
                        </span>
                      </div>
                    </div>

                    {/* Raw header preview */}
                    {hop.raw && (
                      <div className="mt-3 pt-2 border-t border-slate-800/40 text-[10px] font-mono text-slate-500 break-all truncate">
                        Raw: {hop.raw}
                      </div>
                    )}
                  </div>

                  {/* Flow Arrow between hops */}
                  {!isFinal && (
                    <div className="flex justify-center my-1.5 text-cyan-500/60">
                      <ArrowDown className="w-4 h-4 animate-pulse" />
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 text-center font-mono text-xs text-slate-500">
              No Received headers found in parsed email message.
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

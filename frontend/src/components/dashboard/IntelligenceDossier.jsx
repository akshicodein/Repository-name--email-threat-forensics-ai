import React from 'react';
import { 
  Globe, 
  Server, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Clock, 
  Calendar, 
  Building, 
  Lock, 
  Wifi, 
  Database,
  Radio,
  AlertTriangle
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function IntelligenceDossier({ intelligence }) {
  const ipIntelList = intelligence?.ip_intelligence || [];
  const domainIntelList = intelligence?.domain_intelligence || [];

  return (
    <div id="section-intelligence" className="space-y-6">
      <Card
        title="THREAT INTELLIGENCE DOSSIER (IP & DOMAIN ENRICHMENT)"
        subtitle="Network telemetry, registrar WHOIS metadata, and reputation feeds from Member 3"
        icon={Globe}
        badge={<Badge variant="info">MEMBER 3 CONTRACT</Badge>}
        className="border-slate-800"
      >
        {/* IP Intelligence Subsection */}
        <div className="space-y-4 mb-8">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              IP REPUTATION & NETWORK INFRASTRUCTURE ({ipIntelList.length})
            </h4>
            <span className="text-[11px] font-mono text-slate-400">Autonomous Geolocation & ASN Lookup</span>
          </div>

          {ipIntelList.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
              {ipIntelList.map((ipObj, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
                    <div className="flex items-center gap-2">
                      <span className="text-base font-bold text-cyan-300">{ipObj.ip}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        {ipObj.asn || 'ASN Not available'}
                      </span>
                    </div>
                    <Badge
                      variant={
                        ipObj.reputation === 'MALICIOUS' ? 'critical' :
                        ipObj.reputation === 'SUSPICIOUS' ? 'medium' :
                        ipObj.reputation === 'CLEAN' ? 'low' : 'default'
                      }
                      size="xs"
                    >
                      {ipObj.reputation ? ipObj.reputation.toUpperCase() : 'UNKNOWN'}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-400 block">GEOLOCATION</span>
                      <span className="text-slate-200 font-semibold">
                        {ipObj.city ? `${ipObj.city}, ` : ''}{ipObj.country || 'Not available'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">ISP / OPERATOR</span>
                      <span className="text-slate-200 truncate block">
                        {ipObj.isp || ipObj.org || 'Not available'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">HOSTING CLUSTER</span>
                      <span className="text-slate-300">
                        {ipObj.hosting_type || 'DataCenter / VPS'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">ANONYMIZATION</span>
                      <span className={ipObj.is_vpn_or_proxy ? 'text-amber-300 font-bold' : 'text-slate-400'}>
                        {ipObj.is_vpn_or_proxy ? 'VPN / Proxy Node' : ipObj.is_tor ? 'Tor Exit Relay' : 'Direct Route'}
                      </span>
                    </div>
                  </div>

                  {ipObj.note && (
                    <div className="pt-2 border-t border-slate-800/60 text-[10px] text-slate-400 italic">
                      Note: {ipObj.note}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-slate-900/40 text-slate-500 font-mono text-xs text-center">
              No external IP addresses available for threat intelligence enrichment.
            </div>
          )}
        </div>

        {/* Domain Intelligence Subsection */}
        <div className="space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Globe className="w-4 h-4 text-amber-400" />
              DOMAIN REPUTATION & DNS RECORDS ({domainIntelList.length})
            </h4>
            <span className="text-[11px] font-mono text-slate-400">DNS & Registrar WHOIS Evaluation</span>
          </div>

          {domainIntelList.length > 0 ? (
            <div className="space-y-3 font-mono text-xs">
              {domainIntelList.map((dObj, idx) => (
                <div key={idx} className="p-4 rounded-xl bg-[#0f1422] border border-slate-800 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                    <div className="flex items-center gap-2">
                      <span className="text-base font-bold text-amber-300">{dObj.domain}</span>
                      {dObj.is_newly_registered && (
                        <Badge variant="high" size="xs">NEWLY REGISTERED (&lt;30 DAYS)</Badge>
                      )}
                    </div>
                    <Badge variant={dObj.reputation === 'POOR' || dObj.reputation === 'CRITICAL_RISK' ? 'critical' : 'low'} size="xs">
                      REPUTATION: {dObj.reputation || 'UNKNOWN'}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-[11px]">
                    <div>
                      <span className="text-slate-400 block">REGISTRAR</span>
                      <span className="text-slate-200 truncate block">{dObj.registrar || 'Not available'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">CREATION DATE</span>
                      <span className="text-slate-200">{dObj.created_date || 'Not available'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">A-RECORD IPs</span>
                      <span className="text-cyan-300 truncate block">
                        {dObj.a_records && dObj.a_records.length > 0 ? dObj.a_records.join(', ') : 'Not resolved'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">MX RECORDS</span>
                      <span className="text-slate-300 truncate block">
                        {dObj.mx_records && dObj.mx_records.length > 0 ? dObj.mx_records.join(', ') : 'None'}
                      </span>
                    </div>
                  </div>

                  {dObj.flags && dObj.flags.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/60 flex items-center gap-2">
                      <span className="text-[10px] text-slate-400 uppercase">RISK FLAGS:</span>
                      <div className="flex flex-wrap gap-1.5">
                        {dObj.flags.map((flag, fIdx) => (
                          <span key={fIdx} className="text-[10px] px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/40">
                            • {flag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-slate-900/40 text-slate-500 font-mono text-xs text-center">
              No domains enriched in intelligence database.
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

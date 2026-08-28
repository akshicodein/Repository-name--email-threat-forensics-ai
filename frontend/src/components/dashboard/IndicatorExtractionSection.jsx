import React, { useState } from 'react';
import { 
  Layers, 
  Globe, 
  Link, 
  Paperclip, 
  Server, 
  FileCode, 
  ExternalLink, 
  AlertCircle,
  CheckCircle2,
  HardDrive
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function IndicatorExtractionSection({ forensics, intelligence }) {
  const [activeTab, setActiveTab] = useState('all'); // 'all' | 'ips' | 'domains' | 'urls' | 'attachments'

  const indicators = forensics?.indicators || {};
  const ips = indicators.ips || [];
  const domains = indicators.domains || [];
  const urls = indicators.urls || [];
  const attachments = indicators.attachments || [];

  const ipIntelList = intelligence?.ip_intelligence || [];
  const domainIntelList = intelligence?.domain_intelligence || [];

  // Helper to format bytes
  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  return (
    <div id="section-indicators" className="space-y-6">
      <Card
        title="EXTRACTED ARTIFACTS & INDICATORS OF COMPROMISE (IOCs)"
        subtitle="Deconstructed network indicators, domains, URLs, and binary attachments"
        icon={Layers}
        badge={<Badge variant="default">{ips.length + domains.length + urls.length + attachments.length} TOTAL IOCs</Badge>}
        className="border-slate-800"
      >
        {/* Sub-tabs */}
        <div className="flex items-center gap-2 pb-4 mb-4 border-b border-slate-800 overflow-x-auto">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
              activeTab === 'all' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            ALL ARTIFACTS ({ips.length + domains.length + urls.length + attachments.length})
          </button>
          <button
            onClick={() => setActiveTab('ips')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
              activeTab === 'ips' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            IP ADDRESSES ({ips.length})
          </button>
          <button
            onClick={() => setActiveTab('domains')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
              activeTab === 'domains' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            DOMAINS ({domains.length})
          </button>
          <button
            onClick={() => setActiveTab('urls')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
              activeTab === 'urls' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            URLs ({urls.length})
          </button>
          <button
            onClick={() => setActiveTab('attachments')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
              activeTab === 'attachments' ? 'bg-cyan-500 text-slate-950 shadow-md' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            ATTACHMENTS ({attachments.length})
          </button>
        </div>

        {/* IP Addresses Section */}
        {(activeTab === 'all' || activeTab === 'ips') && (
          <div className="space-y-3 mb-6">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              EXTRACTED IP ADDRESSES ({ips.length})
            </h4>
            {ips.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                {ips.map((ip, idx) => {
                  const intel = ipIntelList.find((i) => i.ip === ip);
                  return (
                    <div key={idx} className="p-3.5 rounded-xl bg-[#0f1422] border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyan-300 text-sm">{ip}</span>
                        {intel?.reputation && (
                          <Badge variant={intel.reputation === 'MALICIOUS' ? 'critical' : intel.reputation === 'SUSPICIOUS' ? 'medium' : 'low'} size="xs">
                            {intel.reputation}
                          </Badge>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center justify-between">
                        <span>Source: {idx === 0 ? 'Earliest Observed Hop' : 'Intermediate Relay / Body'}</span>
                        <span>{intel?.country ? `${intel.city || ''}, ${intel.country}` : 'External IP'}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-slate-900/40 text-slate-500 text-xs font-mono">
                No IP addresses extracted from message content.
              </div>
            )}
          </div>
        )}

        {/* Domains Section */}
        {(activeTab === 'all' || activeTab === 'domains') && (
          <div className="space-y-3 mb-6">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-amber-400" />
              EXTRACTED DOMAIN ENTITIES ({domains.length})
            </h4>
            {domains.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                {domains.map((domain, idx) => {
                  const dIntel = domainIntelList.find((d) => d.domain === domain);
                  return (
                    <div key={idx} className="p-3.5 rounded-xl bg-[#0f1422] border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-amber-300">{domain}</span>
                        {dIntel?.is_newly_registered && (
                          <Badge variant="high" size="xs">NEWLY REGISTERED</Badge>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center justify-between">
                        <span>Registrar: {dIntel?.registrar || 'Not available'}</span>
                        <span>{dIntel?.created_date ? `Created: ${dIntel.created_date}` : 'Established Domain'}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-slate-900/40 text-slate-500 text-xs font-mono">
                No domain indicators extracted.
              </div>
            )}
          </div>
        )}

        {/* URLs Section */}
        {(activeTab === 'all' || activeTab === 'urls') && (
          <div className="space-y-3 mb-6">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Link className="w-3.5 h-3.5 text-rose-400" />
              EXTRACTED HYPERLINKS & URLs ({urls.length})
            </h4>
            {urls.length > 0 ? (
              <div className="space-y-2.5 font-mono text-xs">
                {urls.map((u, idx) => {
                  const urlStr = typeof u === 'string' ? u : u.url;
                  const flags = u.flags || [];
                  return (
                    <div key={idx} className="p-3.5 rounded-xl bg-[#0f1422] border border-slate-800 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-rose-300 break-all select-all">{urlStr}</span>
                        <Badge variant="critical" size="xs">SUSPICIOUS URL</Badge>
                      </div>
                      {flags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                          {flags.map((f, fIdx) => (
                            <span key={fIdx} className="text-[10px] px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/40 text-rose-300 font-mono">
                              • {f}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-slate-900/40 text-slate-500 text-xs font-mono">
                No hyperlink URLs found in plain text or HTML body parts.
              </div>
            )}
          </div>
        )}

        {/* Attachments Section */}
        {(activeTab === 'all' || activeTab === 'attachments') && (
          <div className="space-y-3">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Paperclip className="w-3.5 h-3.5 text-emerald-400" />
              ATTACHMENTS & PAYLOAD ARTIFACTS ({attachments.length})
            </h4>
            {attachments.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                {attachments.map((att, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-[#0f1422] border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200">{att.filename || 'unnamed_attachment'}</span>
                      <Badge variant="default" size="xs">{att.content_type || 'application/octet-stream'}</Badge>
                    </div>
                    <div className="text-[11px] text-slate-400 flex items-center justify-between">
                      <span>Size: {formatBytes(att.size_bytes)}</span>
                      <span className="text-cyan-400">Forensic Parsed</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-slate-900/40 text-slate-500 text-xs font-mono">
                No MIME attachments included in email payload.
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

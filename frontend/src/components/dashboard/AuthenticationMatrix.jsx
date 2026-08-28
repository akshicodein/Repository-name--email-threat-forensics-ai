import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  HelpCircle, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Key, 
  Lock, 
  FileSearch,
  Globe
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function AuthenticationMatrix({ forensics }) {
  const auth = forensics?.authentication || {};
  const authDetails = forensics?.headers?.authentication_results || {};
  const anomalies = forensics?.anomalies || [];

  const formatAuthState = (state) => {
    if (!state) return { label: 'UNKNOWN', variant: 'default', icon: HelpCircle, color: 'text-slate-400' };
    const s = state.toLowerCase();
    if (s === 'pass') {
      return { label: 'PASS', variant: 'low', icon: CheckCircle2, color: 'text-emerald-400' };
    }
    if (s === 'fail' || s === 'softfail' || s === 'hardfail') {
      return { label: 'FAIL', variant: 'critical', icon: XCircle, color: 'text-rose-400' };
    }
    if (s === 'none') {
      return { label: 'NONE', variant: 'default', icon: AlertTriangle, color: 'text-amber-400' };
    }
    return { label: state.toUpperCase(), variant: 'medium', icon: HelpCircle, color: 'text-amber-400' };
  };

  const spfStatus = formatAuthState(auth.spf || authDetails.spf);
  const dkimStatus = formatAuthState(auth.dkim || authDetails.dkim);
  const dmarcStatus = formatAuthState(auth.dmarc || authDetails.dmarc);

  const SpfIcon = spfStatus.icon;
  const DkimIcon = dkimStatus.icon;
  const DmarcIcon = dmarcStatus.icon;

  return (
    <div id="section-auth" className="space-y-6">
      <Card
        title="AUTHENTICATION MATRIX & ANOMALY DETECTION"
        subtitle="Cryptographic verification (SPF, DKIM, DMARC) and header alignment consistency"
        icon={ShieldCheck}
        badge={<Badge variant="info">RFC 7208 / 6376 / 7489</Badge>}
        className="border-slate-800"
      >
        {/* Tri-Authentication Matrix Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* SPF Status */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-400">
                SPF (SENDER POLICY FRAMEWORK)
              </span>
              <Badge variant={spfStatus.variant} dot size="xs">
                {spfStatus.label}
              </Badge>
            </div>
            <div className="flex items-center gap-3">
              <div className={`p-2.5 rounded-xl bg-black/40 border border-slate-800 ${spfStatus.color}`}>
                <SpfIcon className="w-6 h-6" />
              </div>
              <div className="text-xs font-mono">
                <span className="text-slate-400 block text-[11px]">AUTHENTICATED DOMAIN:</span>
                <span className="text-slate-200 font-semibold truncate block">
                  {authDetails.spf_domain || <span className="text-slate-400 italic">Not available</span>}
                </span>
              </div>
            </div>
            <p className="text-[11px] text-slate-400 font-sans leading-tight">
              {spfStatus.label === 'PASS' 
                ? 'Sending mail server IP is explicitly authorized in sender DNS records.'
                : spfStatus.label === 'FAIL'
                ? 'Sending server IP is NOT authorized in sender domain SPF record.'
                : 'No SPF record or authentication state available.'}
            </p>
          </div>

          {/* DKIM Status */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-400">
                DKIM (CRYPTOGRAPHIC SIGNATURE)
              </span>
              <Badge variant={dkimStatus.variant} dot size="xs">
                {dkimStatus.label}
              </Badge>
            </div>
            <div className="flex items-center gap-3">
              <div className={`p-2.5 rounded-xl bg-black/40 border border-slate-800 ${dkimStatus.color}`}>
                <DkimIcon className="w-6 h-6" />
              </div>
              <div className="text-xs font-mono">
                <span className="text-slate-400 block text-[11px]">SIGNING DOMAIN (d=):</span>
                <span className="text-slate-200 font-semibold truncate block">
                  {authDetails.dkim_domain || <span className="text-slate-400 italic">No signature found</span>}
                </span>
              </div>
            </div>
            <p className="text-[11px] text-slate-400 font-sans leading-tight">
              {dkimStatus.label === 'PASS'
                ? 'Valid RSA/Ed25519 digital signature verified against public DNS key.'
                : dkimStatus.label === 'FAIL'
                ? 'Digital signature header is invalid or message body has been modified.'
                : 'No DKIM-Signature header present on message.'}
            </p>
          </div>

          {/* DMARC Status */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-slate-400">
                DMARC (POLICY ALIGNMENT)
              </span>
              <Badge variant={dmarcStatus.variant} dot size="xs">
                {dmarcStatus.label}
              </Badge>
            </div>
            <div className="flex items-center gap-3">
              <div className={`p-2.5 rounded-xl bg-black/40 border border-slate-800 ${dmarcStatus.color}`}>
                <DmarcIcon className="w-6 h-6" />
              </div>
              <div className="text-xs font-mono">
                <span className="text-slate-400 block text-[11px]">ALIGNMENT POSTURE:</span>
                <span className="text-slate-200 font-semibold truncate block">
                  {dmarcStatus.label === 'PASS' ? 'Aligned & Compliant' : 'Unaligned / Failed'}
                </span>
              </div>
            </div>
            <p className="text-[11px] text-slate-400 font-sans leading-tight">
              {dmarcStatus.label === 'PASS'
                ? 'From domain strictly aligns with verified SPF and/or DKIM identifier.'
                : dmarcStatus.label === 'FAIL'
                ? 'From domain does NOT align with SPF/DKIM; spoofing protection triggered.'
                : 'No published DMARC policy discovered.'}
            </p>
          </div>
        </div>

        {/* Header Anomalies List */}
        <div className="mt-6 pt-5 border-t border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
              DETECTED FORENSIC HEADER ANOMALIES ({anomalies.length})
            </h4>
            <span className="text-[11px] font-mono text-slate-400">
              Severity-rated by Member 1 Engine
            </span>
          </div>

          {anomalies.length > 0 ? (
            <div className="space-y-2.5">
              {anomalies.map((anom, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-[#0f1422] border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono"
                >
                  <div className="flex items-start gap-3">
                    <span className="p-1 rounded bg-rose-950/60 text-rose-400 border border-rose-800/50 shrink-0 mt-0.5">
                      <AlertTriangle className="w-3.5 h-3.5" />
                    </span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-100 uppercase tracking-wide">
                          {anom.type ? anom.type.replace(/_/g, ' ') : 'Anomaly'}
                        </span>
                        <Badge variant={anom.severity === 'HIGH' ? 'critical' : 'medium'} size="xs">
                          {anom.severity || 'MEDIUM'}
                        </Badge>
                      </div>
                      <p className="text-slate-300 font-sans text-xs mt-1">
                        {anom.description}
                      </p>
                    </div>
                  </div>

                  {anom.evidence && (
                    <div className="text-[11px] text-cyan-300 bg-black/40 px-3 py-1.5 rounded-lg border border-slate-800 shrink-0 max-w-xs break-all">
                      {JSON.stringify(anom.evidence)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 text-xs font-mono text-emerald-400 text-center">
              ✓ No forensic header anomalies found. Header structure is structurally consistent.
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

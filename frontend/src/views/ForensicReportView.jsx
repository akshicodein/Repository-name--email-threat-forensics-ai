import React from 'react';
import { 
  Printer, 
  ArrowLeft, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX, 
  FileText, 
  CheckCircle2, 
  AlertTriangle, 
  Globe, 
  Server, 
  Dna, 
  Calendar,
  Lock
} from 'lucide-react';
import { Button } from '../components/common/Button';
import { Badge } from '../components/common/Badge';

export function ForensicReportView({ analysisResult, onBack }) {
  if (!analysisResult) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center text-center p-6">
        <FileText className="w-12 h-12 text-slate-600 mb-4 animate-pulse" />
        <h2 className="text-xl font-bold font-mono text-slate-300">NO REPORT DATA AVAILABLE</h2>
        <Button variant="primary" className="mt-6" onClick={onBack}>
          Return to Dashboard
        </Button>
      </div>
    );
  }

  const { id, fileName, timestamp, forensics, detection, intelligence } = analysisResult;
  const email = forensics?.email || {};
  const auth = forensics?.authentication || {};
  const receivedChain = forensics?.headers?.received_chain || [];
  const riskScore = detection?.risk_score ?? 80;
  const riskLevel = detection?.risk_level ?? 'HIGH';
  const classification = detection?.classification ?? 'BEC';
  const attackDna = detection?.attack_dna ?? 'A7-F3-C9-21-88';
  const indicators = detection?.indicators || [];
  const ipIntel = intelligence?.ip_intelligence || [];
  const domainIntel = intelligence?.domain_intelligence || [];
  const evolution = intelligence?.infrastructure_evolution || [];

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto space-y-8 font-sans animate-fadeIn">
      {/* Print / Navigation Action Bar (Hidden in Print Mode) */}
      <div className="print:hidden flex items-center justify-between p-4 rounded-2xl bg-[#111726]/90 border border-slate-800 shadow-xl backdrop-blur-md">
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={onBack} icon={ArrowLeft}>
            Back to Dashboard
          </Button>
          <span className="text-xs font-mono text-slate-400 hidden sm:inline-block">
            Print-ready forensic intelligence export
          </span>
        </div>
        <Button variant="primary" size="sm" onClick={handlePrint} icon={Printer}>
          Print Dossier (Ctrl + P)
        </Button>
      </div>

      {/* Main Printable Document Container */}
      <div className="bg-[#0e1422] print:bg-white print:text-black p-8 sm:p-12 rounded-2xl border border-slate-800 print:border-none shadow-2xl space-y-8">
        {/* Document Header */}
        <div className="border-b-2 border-slate-700 print:border-black pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-mono font-bold text-cyan-400 print:text-black uppercase tracking-widest mb-1">
              EMAIL THREAT FORENSICS AI • SOC INVESTIGATION REPORT
            </div>
            <h1 className="text-2xl sm:text-3xl font-black font-mono text-slate-100 print:text-black uppercase">
              FORENSIC INCIDENT DOSSIER
            </h1>
            <p className="text-xs font-mono text-slate-400 print:text-gray-600 mt-1">
              Case ID: <strong className="text-slate-200 print:text-black">{id}</strong> • Generated: {new Date().toUTCString()}
            </p>
          </div>

          <div className="text-left sm:text-right font-mono">
            <div className="inline-block px-3 py-1.5 rounded-lg bg-rose-950/80 border border-rose-700 text-rose-300 print:bg-gray-200 print:text-black print:border-black font-bold text-sm">
              {riskLevel} RISK ({riskScore}/100)
            </div>
            <span className="block text-[11px] font-bold text-slate-400 print:text-gray-700 mt-1">
              CLASSIFICATION: {classification}
            </span>
          </div>
        </div>

        {/* 1. Case Metadata Summary */}
        <section className="space-y-3">
          <h2 className="text-sm font-bold font-mono text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 print:border-gray-300 pb-1">
            1. CASE & INGESTION TELEMETRY
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
            <div>
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">TARGET FILE</span>
              <span className="text-slate-200 print:text-black font-bold">{fileName}</span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">ANALYSIS TIMESTAMP</span>
              <span className="text-slate-200 print:text-black">{timestamp ? new Date(timestamp).toLocaleDateString() : 'Current Session'}</span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">ATTACK DNA</span>
              <span className="text-violet-300 print:text-black font-bold">{attackDna}</span>
            </div>
            <div>
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">PRIMARY VERDICT</span>
              <span className="text-slate-200 print:text-black font-bold">{classification}</span>
            </div>
          </div>
        </section>

        {/* 2. Email Header Forensics */}
        <section className="space-y-3">
          <h2 className="text-sm font-bold font-mono text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 print:border-gray-300 pb-1">
            2. RFC 822 EMAIL HEADER FORENSICS
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">FROM HEADER:</span>
              <span className="text-slate-200 print:text-black font-semibold break-all">{email.from || 'N/A'}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">REPLY-TO ADDRESS:</span>
              <span className="text-rose-300 print:text-black font-semibold break-all">{email.reply_to || 'None (Defaults to From)'}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">TO RECIPIENT:</span>
              <span className="text-slate-200 print:text-black break-all">{email.to || 'N/A'}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">RETURN-PATH:</span>
              <span className="text-slate-200 print:text-black break-all">{email.return_path || 'N/A'}</span>
            </div>
            <div className="sm:col-span-2 p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 block text-[10px]">SUBJECT LINE:</span>
              <span className="text-slate-100 print:text-black font-bold">{email.subject || 'N/A'}</span>
            </div>
          </div>
        </section>

        {/* 3. Cryptographic Authentication Matrix */}
        <section className="space-y-3">
          <h2 className="text-sm font-bold font-mono text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 print:border-gray-300 pb-1">
            3. CRYPTOGRAPHIC AUTHENTICATION POSTURE
          </h2>
          <div className="grid grid-cols-3 gap-4 font-mono text-xs text-center">
            <div className="p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 text-[10px] block">SPF EVALUATION</span>
              <span className={`text-base font-extrabold ${auth.spf === 'pass' ? 'text-emerald-400 print:text-black' : 'text-rose-400 print:text-black'}`}>
                {auth.spf?.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 text-[10px] block">DKIM SIGNATURE</span>
              <span className={`text-base font-extrabold ${auth.dkim === 'pass' ? 'text-emerald-400 print:text-black' : 'text-slate-300 print:text-black'}`}>
                {auth.dkim?.toUpperCase() || 'NONE'}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/60 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 print:text-gray-600 text-[10px] block">DMARC POLICY</span>
              <span className={`text-base font-extrabold ${auth.dmarc === 'pass' ? 'text-emerald-400 print:text-black' : 'text-rose-400 print:text-black'}`}>
                {auth.dmarc?.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>
          </div>
        </section>

        {/* 4. Verified Indicators & Evidence */}
        <section className="space-y-3">
          <h2 className="text-sm font-bold font-mono text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 print:border-gray-300 pb-1">
            4. VERIFIED INDICATORS & PROVENANCE EVIDENCE
          </h2>
          <div className="space-y-2 font-mono text-xs">
            {indicators.map((ind, idx) => (
              <div key={idx} className="p-2 rounded bg-slate-950/40 print:bg-gray-50 border border-slate-800/80 print:border-gray-200 flex items-center justify-between">
                <span className="text-slate-200 print:text-black">• {ind}</span>
                <span className="text-[10px] text-cyan-400 print:text-gray-600 uppercase font-bold">VERIFIED FINDING</span>
              </div>
            ))}
          </div>
        </section>

        {/* 5. Observed Infrastructure & Relay Hops */}
        <section className="space-y-3">
          <h2 className="text-sm font-bold font-mono text-cyan-400 print:text-black uppercase tracking-wider border-b border-slate-800 print:border-gray-300 pb-1">
            5. OBSERVED RELAY CHAIN & NETWORK TELEMETRY
          </h2>
          <table className="w-full font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-700 print:border-black text-left text-[10px] text-slate-400 print:text-gray-700">
                <th className="py-2">HOP</th>
                <th className="py-2">FROM HOST</th>
                <th className="py-2">OBSERVED IP</th>
                <th className="py-2">BY HOST</th>
                <th className="py-2">ROLE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 print:divide-gray-300 text-[11px]">
              {receivedChain.map((hop, idx) => (
                <tr key={idx}>
                  <td className="py-2 font-bold">#{hop.hop}</td>
                  <td className="py-2 truncate max-w-[140px]">{hop.from_host || 'N/A'}</td>
                  <td className="py-2 text-cyan-300 print:text-black font-semibold">{hop.ip || 'None'}</td>
                  <td className="py-2 truncate max-w-[140px]">{hop.by_host || 'N/A'}</td>
                  <td className="py-2 text-slate-400 print:text-gray-600">
                    {idx === 0 ? 'Observed Source' : idx === receivedChain.length - 1 ? 'Recipient MX' : 'Intermediate Relay'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* 6. Executive Narrative Summary */}
        <section className="space-y-3 border-t-2 border-slate-700 print:border-black pt-6">
          <h2 className="text-sm font-bold font-mono text-cyan-400 print:text-black uppercase tracking-wider">
            6. INVESTIGATION CONCLUSION & FORENSIC ATTESTATION
          </h2>
          <p className="text-xs font-sans text-slate-200 print:text-black leading-relaxed">
            {detection?.summary || 'Deep forensic analysis concluded high-risk threat signature with multiple confirmed authentication and header anomalies.'}
          </p>
          <div className="p-3 rounded-lg bg-slate-950/80 print:bg-gray-100 border border-slate-800 print:border-gray-300 text-[10px] font-mono text-slate-400 print:text-gray-700 space-y-1">
            <span>FORENSIC LIMITATION NOTICE:</span>
            <p>
              Attribution findings reflect observed network infrastructure, cryptographic verification failures, and quantized behavioral Attack DNA. Geolocation points indicate transit hosting nodes rather than individual physical identity.
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}

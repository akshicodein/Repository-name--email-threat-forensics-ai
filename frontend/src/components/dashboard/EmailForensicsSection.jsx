import React, { useState } from 'react';
import { 
  Mail, 
  FileText, 
  Code, 
  ChevronDown, 
  ChevronUp, 
  AlertTriangle, 
  Calendar, 
  Hash, 
  User, 
  Send, 
  CornerDownRight, 
  RotateCcw,
  CheckCircle2
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function EmailForensicsSection({ forensics }) {
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [showBodyPreview, setShowBodyPreview] = useState(true);

  const email = forensics?.email || {};
  const rawHeaders = forensics?.headers?.raw_relevant_headers || {};
  const receivedChain = forensics?.headers?.received_chain || [];

  // Extract domain helper
  const extractDomain = (addr) => {
    if (!addr) return '';
    const match = addr.match(/@([\w.-]+)/);
    return match ? match[1].toLowerCase() : '';
  };

  const fromDomain = extractDomain(email.from);
  const replyToDomain = extractDomain(email.reply_to);
  const returnPathDomain = extractDomain(email.return_path);

  const hasReplyToMismatch = replyToDomain && fromDomain && replyToDomain !== fromDomain;
  const hasReturnPathMismatch = returnPathDomain && fromDomain && returnPathDomain !== fromDomain;

  return (
    <div id="section-forensics" className="space-y-6">
      <Card
        title="EMAIL FORENSICS & HEADER DOSSIER"
        subtitle="RFC 822 forensic metadata extracted by Member 1 Forensics Engine"
        icon={Mail}
        badge={<Badge variant="default">MEMBER 1 CONTRACT</Badge>}
        className="border-slate-800"
      >
        {/* Core Field Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {/* Subject */}
          <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 md:col-span-2 space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                SUBJECT LINE
              </span>
              <span className="text-[10px] text-slate-400">RFC: Subject</span>
            </div>
            <p className="text-sm font-semibold text-slate-100 font-sans">
              {email.subject || <span className="text-slate-400 italic">Not available</span>}
            </p>
          </div>

          {/* From Header */}
          <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                FROM (DISPLAY SENDER)
              </span>
              <span className="text-[10px] text-slate-400">RFC: From</span>
            </div>
            <p className="text-xs font-semibold text-slate-200 break-all">
              {email.from || <span className="text-slate-400 italic">Not available</span>}
            </p>
            {fromDomain && (
              <span className="text-[11px] text-cyan-400 block pt-0.5">
                Domain: {fromDomain}
              </span>
            )}
          </div>

          {/* Reply-To Header */}
          <div className={`p-3.5 rounded-xl border space-y-1 ${
            hasReplyToMismatch 
              ? 'bg-rose-950/20 border-rose-800/60 text-rose-300' 
              : 'bg-slate-900/70 border-slate-800 text-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                REPLY-TO ADDRESS
              </span>
              {hasReplyToMismatch ? (
                <span className="text-[10px] text-rose-400 font-bold flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> MISMATCH DETECTED
                </span>
              ) : (
                <span className="text-[10px] text-slate-400">RFC: Reply-To</span>
              )}
            </div>
            <p className="text-xs font-semibold break-all">
              {email.reply_to || <span className="text-slate-400 italic">None configured (defaults to From)</span>}
            </p>
            {hasReplyToMismatch && (
              <p className="text-[11px] text-rose-400 leading-tight pt-1">
                ⚠️ Directs replies to <span className="font-bold underline">{replyToDomain}</span> instead of sender domain <span className="font-bold">{fromDomain}</span>.
              </p>
            )}
          </div>

          {/* To Header */}
          <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                TO (RECIPIENT)
              </span>
              <span className="text-[10px] text-slate-400">RFC: To</span>
            </div>
            <p className="text-xs font-semibold text-slate-200 break-all">
              {email.to || <span className="text-slate-400 italic">Not available</span>}
            </p>
          </div>

          {/* Return-Path */}
          <div className={`p-3.5 rounded-xl border space-y-1 ${
            hasReturnPathMismatch
              ? 'bg-amber-950/20 border-amber-800/60 text-amber-300'
              : 'bg-slate-900/70 border-slate-800 text-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                RETURN-PATH (ENVELOPE FROM)
              </span>
              <span className="text-[10px] text-slate-400">RFC: Return-Path</span>
            </div>
            <p className="text-xs font-semibold break-all">
              {email.return_path || <span className="text-slate-400 italic">Not available</span>}
            </p>
          </div>

          {/* Date & Timestamp */}
          <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                ORIGINATION DATE
              </span>
              <Calendar className="w-3.5 h-3.5 text-slate-400" />
            </div>
            <p className="text-xs font-semibold text-slate-200">
              {email.date || <span className="text-slate-400 italic">Not available</span>}
            </p>
          </div>

          {/* Message-ID */}
          <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                MESSAGE-ID
              </span>
              <Hash className="w-3.5 h-3.5 text-slate-400" />
            </div>
            <p className="text-xs font-semibold text-cyan-300 break-all">
              {email.message_id || <span className="text-slate-400 italic">Not available</span>}
            </p>
          </div>
        </div>

        {/* Body Content Preview Accordion */}
        {email.body_preview && (
          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <button
              onClick={() => setShowBodyPreview(!showBodyPreview)}
              className="flex items-center justify-between w-full py-2 text-xs font-mono font-bold text-slate-300 hover:text-white"
            >
              <span className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                PARSED EMAIL BODY PREVIEW
              </span>
              {showBodyPreview ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
            {showBodyPreview && (
              <div className="p-4 mt-2 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed">
                {email.body_preview}
              </div>
            )}
          </div>
        )}

        {/* Raw Relevant Headers Inspector */}
        <div className="mt-4 pt-3 border-t border-slate-800/80">
          <button
            onClick={() => setShowRawHeaders(!showRawHeaders)}
            className="flex items-center justify-between w-full py-2 text-xs font-mono font-bold text-slate-400 hover:text-cyan-300 transition-colors"
          >
            <span className="flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              INSPECT RAW RELEVANT RFC 822 HEADERS
            </span>
            {showRawHeaders ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showRawHeaders && (
            <div className="p-4 mt-2 rounded-xl bg-black/70 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto space-y-1.5 max-h-64">
              {Object.entries(rawHeaders).length > 0 ? (
                Object.entries(rawHeaders).map(([key, val]) => (
                  <div key={key} className="break-all">
                    <span className="text-slate-400 font-bold">{key}:</span> {val}
                  </div>
                ))
              ) : (
                <div className="text-slate-500 italic">No additional raw relevant headers available.</div>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

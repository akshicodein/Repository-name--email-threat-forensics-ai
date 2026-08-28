import React from 'react';
import { Handle, Position } from '@xyflow/react';
import { 
  Mail, 
  Globe, 
  Server, 
  Link, 
  ShieldAlert, 
  Dna, 
  Activity, 
  Database,
  Radio,
  FileCode
} from 'lucide-react';

const ENTITY_CONFIG = {
  Email: {
    icon: Mail,
    border: 'border-cyan-500',
    bg: 'bg-[#0f192b]/95',
    text: 'text-cyan-300',
    badge: 'bg-cyan-950 text-cyan-400 border-cyan-800',
    label: 'EMAIL ENTITY',
  },
  Domain: {
    icon: Globe,
    border: 'border-amber-500',
    bg: 'bg-[#1e1910]/95',
    text: 'text-amber-300',
    badge: 'bg-amber-950 text-amber-400 border-amber-800',
    label: 'DOMAIN ENTITY',
  },
  IP: {
    icon: Server,
    border: 'border-rose-500',
    bg: 'bg-[#220f14]/95',
    text: 'text-rose-300',
    badge: 'bg-rose-950 text-rose-400 border-rose-800',
    label: 'OBSERVED IP',
  },
  URL: {
    icon: Link,
    border: 'border-pink-500',
    bg: 'bg-[#220f1a]/95',
    text: 'text-pink-300',
    badge: 'bg-pink-950 text-pink-400 border-pink-800',
    label: 'EXTRACTED URL',
  },
  ASN: {
    icon: Radio,
    border: 'border-blue-500',
    bg: 'bg-[#0f172a]/95',
    text: 'text-blue-300',
    badge: 'bg-blue-950 text-blue-400 border-blue-800',
    label: 'AUTONOMOUS SYSTEM',
  },
  AttackDNA: {
    icon: Dna,
    border: 'border-violet-500',
    bg: 'bg-[#1b122c]/95',
    text: 'text-violet-300',
    badge: 'bg-violet-950 text-violet-400 border-violet-800',
    label: 'ATTACK DNA',
  },
  Case: {
    icon: Database,
    border: 'border-emerald-500',
    bg: 'bg-[#0e211a]/95',
    text: 'text-emerald-300',
    badge: 'bg-emerald-950 text-emerald-400 border-emerald-800',
    label: 'HISTORICAL CASE',
  },
  Campaign: {
    icon: Activity,
    border: 'border-orange-500',
    bg: 'bg-[#24140a]/95',
    text: 'text-orange-300',
    badge: 'bg-orange-950 text-orange-400 border-orange-800',
    label: 'CAMPAIGN CLUSTER',
  },
};

export function CustomEntityNode({ data, selected }) {
  const type = data.type || 'Email';
  const config = ENTITY_CONFIG[type] || ENTITY_CONFIG.Email;
  const Icon = config.icon;

  return (
    <div
      className={`relative px-3.5 py-2.5 rounded-xl border-2 shadow-2xl backdrop-blur-md transition-all font-mono min-w-[180px] max-w-[260px] ${
        config.bg
      } ${config.border} ${
        selected ? 'ring-4 ring-cyan-400/50 scale-105 shadow-cyan-950/50' : 'hover:scale-[1.02]'
      }`}
    >
      {/* Target & Source Connection Handles */}
      <Handle
        type="target"
        position={Position.Top}
        className="w-2.5 h-2.5 !bg-cyan-400 !border-2 !border-slate-950"
      />
      <Handle
        type="target"
        position={Position.Left}
        id="left"
        className="w-2.5 h-2.5 !bg-cyan-400 !border-2 !border-slate-950"
      />

      <div className="flex items-center justify-between gap-2 mb-1">
        <span
          className={`text-[9px] font-bold px-1.5 py-0.2 rounded border uppercase tracking-wider ${config.badge}`}
        >
          {config.label}
        </span>
        {data.certainty && (
          <span className="text-[9px] text-slate-400 uppercase font-semibold">
            {data.certainty}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2 mt-1.5">
        <div className={`p-1.5 rounded-lg bg-black/40 ${config.text} shrink-0`}>
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className={`text-xs font-bold truncate ${config.text}`}>
            {data.label || 'Unnamed Entity'}
          </div>
          {data.subtext && (
            <div className="text-[10px] text-slate-400 truncate mt-0.5">
              {data.subtext}
            </div>
          )}
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="w-2.5 h-2.5 !bg-cyan-400 !border-2 !border-slate-950"
      />
      <Handle
        type="source"
        position={Position.Right}
        id="right"
        className="w-2.5 h-2.5 !bg-cyan-400 !border-2 !border-slate-950"
      />
    </div>
  );
}

import React from 'react';
import { clsx } from 'clsx';
import { ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, Cpu } from 'lucide-react';

export function StatusIndicator({
  level = 'low', // 'low' | 'medium' | 'high' | 'critical' | 'info'
  score,
  label,
  showIcon = true,
  size = 'md',
  className = '',
}) {
  const normLevel = (level || '').toLowerCase();

  const config = {
    critical: {
      color: 'text-rose-400',
      bg: 'bg-rose-950/40',
      border: 'border-rose-800/80',
      glow: 'shadow-rose-900/30',
      icon: ShieldX,
      label: label || 'CRITICAL THREAT',
    },
    high: {
      color: 'text-orange-400',
      bg: 'bg-orange-950/40',
      border: 'border-orange-800/80',
      glow: 'shadow-orange-900/30',
      icon: ShieldAlert,
      label: label || 'HIGH RISK',
    },
    medium: {
      color: 'text-amber-400',
      bg: 'bg-amber-950/40',
      border: 'border-amber-800/80',
      glow: 'shadow-amber-900/30',
      icon: AlertTriangle,
      label: label || 'SUSPICIOUS',
    },
    low: {
      color: 'text-emerald-400',
      bg: 'bg-emerald-950/40',
      border: 'border-emerald-800/80',
      glow: 'shadow-emerald-900/30',
      icon: ShieldCheck,
      label: label || 'LEGITIMATE / CLEAN',
    },
    info: {
      color: 'text-cyan-400',
      bg: 'bg-cyan-950/40',
      border: 'border-cyan-800/80',
      glow: 'shadow-cyan-900/30',
      icon: Cpu,
      label: label || 'ANALYZING',
    }
  };

  const active = config[normLevel] || config.low;
  const Icon = active.icon;

  const sizeClasses = {
    sm: 'px-2.5 py-1 text-xs gap-1.5',
    md: 'px-3.5 py-2 text-sm gap-2.5',
    lg: 'px-5 py-3 text-base gap-3.5',
  };

  return (
    <div
      className={clsx(
        'inline-flex items-center rounded-xl border backdrop-blur-md shadow-lg',
        active.bg,
        active.border,
        active.color,
        active.glow,
        sizeClasses[size],
        className
      )}
    >
      {showIcon && <Icon className={clsx(size === 'lg' ? 'w-6 h-6' : 'w-4 h-4', 'shrink-0')} />}
      <div className="flex items-baseline gap-2 font-mono">
        <span className="font-bold tracking-wider">{active.label}</span>
        {score !== undefined && (
          <span className="font-extrabold text-xs opacity-90 px-1.5 py-0.5 rounded bg-black/40 border border-white/10">
            {score}/100
          </span>
        )}
      </div>
    </div>
  );
}

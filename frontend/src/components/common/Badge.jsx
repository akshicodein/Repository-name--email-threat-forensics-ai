import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function Badge({
  children,
  className,
  variant = 'default',
  size = 'sm',
  dot = false,
  ...props
}) {
  const baseStyles = 'inline-flex items-center font-medium rounded-md border tracking-wide uppercase font-mono';

  const variants = {
    default: 'bg-slate-800/80 text-slate-300 border-slate-700',
    critical: 'bg-rose-950/50 text-rose-300 border-rose-800/60 shadow-sm shadow-rose-950/50',
    high: 'bg-orange-950/50 text-orange-300 border-orange-800/60',
    medium: 'bg-amber-950/50 text-amber-300 border-amber-800/60',
    low: 'bg-emerald-950/50 text-emerald-300 border-emerald-800/60',
    info: 'bg-cyan-950/50 text-cyan-300 border-cyan-800/60',
    dna: 'bg-violet-950/50 text-violet-300 border-violet-800/60',
  };

  const dotColors = {
    default: 'bg-slate-400',
    critical: 'bg-rose-500 animate-pulse',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-emerald-500',
    info: 'bg-cyan-400',
    dna: 'bg-violet-400',
  };

  const sizes = {
    xs: 'text-[10px] px-1.5 py-0.5 gap-1',
    sm: 'text-xs px-2 py-0.5 gap-1.5',
    md: 'text-sm px-2.5 py-1 gap-1.5',
  };

  return (
    <span className={twMerge(clsx(baseStyles, variants[variant], sizes[size], className))} {...props}>
      {dot && <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', dotColors[variant] || 'bg-slate-400')} />}
      {children}
    </span>
  );
}

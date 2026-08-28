import React from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function Card({
  children,
  className,
  title,
  subtitle,
  icon: Icon,
  badge,
  action,
  hoverable = false,
  bordered = true,
  ...props
}) {
  return (
    <div
      className={twMerge(
        clsx(
          'bg-[#111726]/80 backdrop-blur-md rounded-xl p-5 transition-all duration-200',
          bordered && 'border border-slate-800/80 shadow-lg shadow-black/40',
          hoverable && 'hover:border-slate-700 hover:bg-[#161f33]/90 hover:shadow-cyan-950/20',
          className
        )
      )}
      {...props}
    >
      {(title || Icon || badge || action) && (
        <div className="flex items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-800/60">
          <div className="flex items-center gap-2.5">
            {Icon && (
              <div className="p-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/40 text-cyan-400">
                <Icon className="w-4 h-4" />
              </div>
            )}
            <div>
              {title && <h3 className="text-sm font-semibold text-slate-100 tracking-wide">{title}</h3>}
              {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {badge}
            {action}
          </div>
        </div>
      )}
      {children}
    </div>
  );
}

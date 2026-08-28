import React from 'react';

export function RiskGauge({ score = 0, level = 'LOW', size = 180 }) {
  const clampedScore = Math.max(0, Math.min(100, score));
  
  // Calculate SVG arc parameters
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const center = size / 2;
  const circumference = radius * 2 * Math.PI;
  // 240 degree gauge arc (from 150 deg to 390 deg)
  const arcLength = circumference * (240 / 360);
  const strokeDashoffset = arcLength - (clampedScore / 100) * arcLength;

  const getColor = (s) => {
    if (s >= 80) return { stroke: '#ef4444', text: 'text-rose-400', glow: 'rgba(239, 68, 68, 0.4)' };
    if (s >= 55) return { stroke: '#f97316', text: 'text-orange-400', glow: 'rgba(249, 115, 22, 0.4)' };
    if (s >= 30) return { stroke: '#f59e0b', text: 'text-amber-400', glow: 'rgba(245, 158, 11, 0.4)' };
    return { stroke: '#10b981', text: 'text-emerald-400', glow: 'rgba(16, 185, 129, 0.4)' };
  };

  const color = getColor(clampedScore);

  return (
    <div className="relative flex flex-col items-center justify-center">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="transform -rotate-[210deg] overflow-visible"
      >
        {/* Background Track Arc */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="transparent"
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeLinecap="round"
        />

        {/* Dynamic Progress Arc */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="transparent"
          stroke={color.stroke}
          strokeWidth={strokeWidth}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
          style={{
            filter: `drop-shadow(0 0 8px ${color.glow})`,
          }}
        />
      </svg>

      {/* Center Score & Threat Label Display */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none mt-2 font-mono">
        <span className="text-4xl sm:text-5xl font-black text-slate-100 tracking-tight">
          {clampedScore}
        </span>
        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-widest mt-0.5">
          / 100 RISK
        </span>
        <span className={`text-xs font-black uppercase tracking-wider px-2 py-0.5 rounded-full mt-1 bg-black/40 border border-white/10 ${color.text}`}>
          {level}
        </span>
      </div>
    </div>
  );
}

import React from 'react';
import { 
  MapPin, 
  Globe, 
  Info, 
  Server, 
  Compass, 
  ShieldAlert,
  Radio
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function ObservedGeoLocation({ intelligence }) {
  const ipIntelList = intelligence?.ip_intelligence || [];
  const primaryIp = ipIntelList[0] || null;

  return (
    <div id="section-geo" className="space-y-6">
      <Card
        title="OBSERVED INFRASTRUCTURE LOCATION"
        subtitle="Geographic network positioning of observed routing hops"
        icon={MapPin}
        badge={<Badge variant="default">GEOLOCATION TELEMETRY</Badge>}
        className="border-slate-800"
      >
        {/* Critical Forensic Disclaimer */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-cyan-800/40 text-slate-300 text-xs font-mono flex items-start gap-3 mb-6">
          <Info className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-cyan-300 uppercase tracking-wider block">
              FORENSIC ACCURACY STATEMENT:
            </span>
            <p className="text-slate-400 leading-relaxed font-sans">
              IP geolocation identifies the <strong>registered physical or administrative location of the network infrastructure</strong> (e.g. data centers, proxy servers, VPS nodes, or BGP autonomous systems). It does <strong>not</strong> represent the physical residence or personal identity of an individual threat actor.
            </p>
          </div>
        </div>

        {primaryIp ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Geo Telemetry Card (5 cols) */}
            <div className="lg:col-span-5 p-5 rounded-xl bg-[#0f1422] border border-slate-800 space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Radio className="w-4 h-4 text-rose-400 animate-pulse" />
                  <span className="font-bold text-slate-100 text-sm">{primaryIp.ip}</span>
                </div>
                <Badge variant={primaryIp.reputation === 'MALICIOUS' ? 'critical' : 'medium'}>
                  {primaryIp.reputation || 'SUSPICIOUS'}
                </Badge>
              </div>

              <div className="space-y-2.5 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">CITY / REGION:</span>
                  <span className="text-slate-200 font-semibold">
                    {primaryIp.city ? `${primaryIp.city}, ` : ''}{primaryIp.region || 'Not available'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">COUNTRY:</span>
                  <span className="text-cyan-300 font-bold">
                    {primaryIp.country || 'Not available'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">AUTONOMOUS SYSTEM:</span>
                  <span className="text-slate-200">
                    {primaryIp.asn || 'Not available'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">NETWORK OPERATOR:</span>
                  <span className="text-slate-200 truncate max-w-[180px]">
                    {primaryIp.isp || primaryIp.org || 'Not available'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">INFRASTRUCTURE TYPE:</span>
                  <span className="text-slate-300">
                    {primaryIp.hosting_type || 'DataCenter / Cloud Host'}
                  </span>
                </div>
              </div>
            </div>

            {/* Simulated Radar Visualizer (7 cols) */}
            <div className="lg:col-span-7 p-6 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col items-center justify-center text-center relative overflow-hidden min-h-[220px]">
              {/* Radar Rings Background */}
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-20">
                <div className="w-64 h-64 rounded-full border border-cyan-500 animate-pulse-subtle" />
                <div className="w-44 h-44 rounded-full border border-cyan-500 absolute" />
                <div className="w-24 h-24 rounded-full border border-cyan-500 absolute" />
                <div className="w-full h-px bg-cyan-500/50 absolute" />
                <div className="h-full w-px bg-cyan-500/50 absolute" />
              </div>

              <div className="relative z-10 space-y-3 font-mono">
                <div className="inline-flex p-3 rounded-full bg-cyan-950/80 border border-cyan-500 text-cyan-400 shadow-xl shadow-cyan-950/80 animate-bounce">
                  <MapPin className="w-6 h-6" />
                </div>
                <div>
                  <h4 className="text-base font-bold text-slate-100">
                    {primaryIp.city ? `${primaryIp.city}, ` : ''}{primaryIp.country}
                  </h4>
                  <p className="text-xs text-cyan-400 mt-0.5">
                    Target Network Node: {primaryIp.ip} ({primaryIp.asn})
                  </p>
                </div>
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                  Observed Network Transit Point • Hosting Facility
                </span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-6 rounded-xl bg-slate-900/40 text-center font-mono text-xs text-slate-500">
            No geographic infrastructure indicators extracted for this case.
          </div>
        )}
      </Card>
    </div>
  );
}

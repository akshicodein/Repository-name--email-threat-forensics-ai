import React, { useState } from 'react';
import { 
  Calendar, 
  GitCommit, 
  Server, 
  Globe, 
  Radio, 
  ShieldAlert, 
  Info, 
  X, 
  ArrowRight,
  Clock,
  Layers
} from 'lucide-react';
import { Card } from '../common/Card';
import { Badge } from '../common/Badge';

export function InfrastructureTimeline({ intelligence }) {
  const [selectedEvent, setSelectedEvent] = useState(null);
  const evolution = intelligence?.infrastructure_evolution || [];

  return (
    <div className="space-y-6">
      <Card
        title="INFRASTRUCTURE EVOLUTION & ROTATION TIMELINE"
        subtitle="Chronological observation of domain registrations, IP mutations, and hosting provider transitions"
        icon={Calendar}
        badge={<Badge variant="default">{evolution.length} ROTATION EVENTS</Badge>}
        className="border-slate-800"
      >
        {/* Attribution & Rotation Framing Note */}
        <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 text-slate-300 text-xs font-mono flex items-start gap-3 mb-6">
          <Info className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-cyan-300 uppercase tracking-wider block">
              INFRASTRUCTURE ROTATION PATTERN:
            </span>
            <p className="text-slate-400 font-sans leading-relaxed">
              Events depict <strong>observed infrastructure changes across correlated incidents</strong>. Shifting domain resolutions and server hosting providers represent tactical infrastructure turnover rather than verified individual physical movement.
            </p>
          </div>
        </div>

        {evolution.length > 0 ? (
          <div className="relative pl-6 sm:pl-8 space-y-6 border-l-2 border-slate-800/80 my-4">
            {evolution.map((event, idx) => {
              const isCurrentIncident = idx === evolution.length - 1;

              return (
                <div key={idx} className="relative group">
                  {/* Timeline Node Bullet */}
                  <div
                    className={`absolute -left-[31px] sm:-left-[39px] top-1.5 w-4 h-4 rounded-full border-2 transition-all cursor-pointer ${
                      isCurrentIncident
                        ? 'bg-cyan-500 border-cyan-300 shadow-md shadow-cyan-500/50 scale-110'
                        : 'bg-slate-900 border-cyan-500/60 group-hover:bg-cyan-400'
                    }`}
                    onClick={() => setSelectedEvent(event)}
                  />

                  {/* Event Card */}
                  <div
                    onClick={() => setSelectedEvent(event)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer font-mono ${
                      isCurrentIncident
                        ? 'bg-cyan-950/20 border-cyan-600/60 shadow-lg shadow-cyan-950/30'
                        : 'bg-[#0f1422] border-slate-800 hover:border-slate-700 hover:bg-slate-900/80'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 mb-2 border-b border-slate-800/60 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-300 font-extrabold">{event.date}</span>
                        {isCurrentIncident && (
                          <Badge variant="info" size="xs">CURRENT INCIDENT</Badge>
                        )}
                        {event.case_id && (
                          <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300 text-[10px]">
                            {event.case_id}
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] text-slate-400">
                        Observed Rotation #{idx + 1}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs my-2">
                      <div>
                        <span className="text-[10px] text-slate-400 block uppercase">DOMAIN ENTITY</span>
                        <span className="text-amber-300 font-bold break-all">
                          {event.domain || 'Not recorded'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] text-slate-400 block uppercase">OBSERVED IP</span>
                        <span className="text-rose-300 font-bold break-all">
                          {event.ip || 'Not recorded'}
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300 font-sans leading-relaxed pt-1">
                      {event.note}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="p-8 rounded-xl bg-slate-900/40 border border-slate-800 text-center font-mono text-xs text-slate-500">
            No previous historical infrastructure rotation timeline recorded for this entity cluster.
          </div>
        )}

        {/* Selected Event Modal */}
        {selectedEvent && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
            <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 max-w-lg w-full font-mono text-xs space-y-4 shadow-2xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Badge variant="info" size="xs">EVENT DETAILS</Badge>
                  <span className="font-bold text-slate-200">{selectedEvent.date}</span>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2.5">
                <div>
                  <span className="text-slate-400 block text-[10px]">ASSOCIATED CASE:</span>
                  <span className="text-cyan-300 font-bold">{selectedEvent.case_id || 'Not specified'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">DOMAIN OBSERVED:</span>
                  <span className="text-amber-300 font-bold">{selectedEvent.domain || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">IP ADDRESS OBSERVED:</span>
                  <span className="text-rose-300 font-bold">{selectedEvent.ip || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">FORENSIC CONTEXT & NOTES:</span>
                  <p className="text-slate-200 font-sans text-xs mt-1 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                    {selectedEvent.note}
                  </p>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 text-right">
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold font-mono"
                >
                  Close Inspector
                </button>
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

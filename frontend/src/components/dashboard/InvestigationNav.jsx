import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  HelpCircle, 
  Mail, 
  ShieldCheck, 
  Layers, 
  GitBranch, 
  Globe, 
  Dna, 
  Database,
  MapPin
} from 'lucide-react';

const SECTIONS = [
  { id: 'section-overview', label: 'OVERVIEW', icon: ShieldAlert },
  { id: 'section-why', label: 'WHY SUSPICIOUS', icon: HelpCircle },
  { id: 'section-forensics', label: 'FORENSICS', icon: Mail },
  { id: 'section-auth', label: 'AUTHENTICATION', icon: ShieldCheck },
  { id: 'section-indicators', label: 'INDICATORS', icon: Layers },
  { id: 'section-relay', label: 'RELAY PATH', icon: GitBranch },
  { id: 'section-intelligence', label: 'IP & DOMAIN INTEL', icon: Globe },
  { id: 'section-geo', label: 'GEO LOCATION', icon: MapPin },
  { id: 'section-attack-dna', label: 'ATTACK DNA', icon: Dna },
  { id: 'section-threat-memory', label: 'THREAT MEMORY', icon: Database },
];

export function InvestigationNav() {
  const [activeSection, setActiveSection] = useState('section-overview');

  useEffect(() => {
    const handleScroll = () => {
      const scrollPosition = window.scrollY + 140;
      
      for (const section of SECTIONS) {
        const el = document.getElementById(section.id);
        if (el) {
          const top = el.offsetTop;
          const height = el.offsetHeight;
          if (scrollPosition >= top && scrollPosition < top + height) {
            setActiveSection(section.id);
            break;
          }
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (id) => {
    const element = document.getElementById(id);
    if (element) {
      const yOffset = -80;
      const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: 'smooth' });
      setActiveSection(id);
    }
  };

  return (
    <div className="sticky top-[61px] z-30 w-full bg-[#0d121f]/95 backdrop-blur-md border-b border-slate-800/80 shadow-lg px-4 lg:px-8 py-2">
      <div className="max-w-7xl mx-auto flex items-center gap-1.5 overflow-x-auto no-scrollbar scroll-smooth">
        <span className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider shrink-0 mr-1.5 hidden xl:inline-block">
          INVESTIGATION DOSSIER:
        </span>
        {SECTIONS.map((sec) => {
          const Icon = sec.icon;
          const isActive = activeSection === sec.id;
          return (
            <button
              key={sec.id}
              onClick={() => scrollToSection(sec.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold tracking-wider whitespace-nowrap transition-all duration-150 shrink-0 ${
                isActive
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{sec.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

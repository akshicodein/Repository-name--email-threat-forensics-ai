import React from 'react';
import { Cpu, ArrowLeft, Network } from 'lucide-react';
import { Button } from '../components/common/Button';
import { InvestigationNav } from '../components/dashboard/InvestigationNav';
import { HeroThreatOverview } from '../components/dashboard/HeroThreatOverview';
import { WhySuspiciousEvidence } from '../components/dashboard/WhySuspiciousEvidence';
import { EmailForensicsSection } from '../components/dashboard/EmailForensicsSection';
import { AuthenticationMatrix } from '../components/dashboard/AuthenticationMatrix';
import { IndicatorExtractionSection } from '../components/dashboard/IndicatorExtractionSection';
import { ObservedRelayPath } from '../components/dashboard/ObservedRelayPath';
import { IntelligenceDossier } from '../components/dashboard/IntelligenceDossier';
import { ObservedGeoLocation } from '../components/dashboard/ObservedGeoLocation';
import { AttackDnaExplainer } from '../components/dashboard/AttackDnaExplainer';
import { ThreatMemoryMatches } from '../components/dashboard/ThreatMemoryMatches';

export function DashboardView({ analysisResult, onReset, onViewGraph }) {
  if (!analysisResult) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center text-center p-6">
        <Cpu className="w-12 h-12 text-slate-600 mb-4 animate-pulse" />
        <h2 className="text-xl font-bold font-mono text-slate-300">NO ACTIVE THREAT INVESTIGATION</h2>
        <p className="text-sm text-slate-500 mt-2 max-w-md">
          Please upload a suspicious .eml email file or select a preset sample to initialize forensic analysis.
        </p>
        <Button variant="primary" className="mt-6" onClick={onReset}>
          Go to Ingestion
        </Button>
      </div>
    );
  }

  const { forensics, detection, intelligence } = analysisResult;

  return (
    <div className="relative pb-20 animate-fadeIn">
      {/* Sticky Quick-Jump Sub-Navigation Bar */}
      <InvestigationNav />

      {/* Main Investigation Dossier Container */}
      <div className="py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto space-y-12">
        {/* 1. Hero Threat Overview & Risk Gauge */}
        <HeroThreatOverview
          analysisResult={analysisResult}
          onReset={onReset}
          onViewGraph={onViewGraph}
        />

        {/* 2. Why is this Suspicious? Dedicated Evidence Dossier */}
        <WhySuspiciousEvidence
          detection={detection}
          forensics={forensics}
        />

        {/* 3. RFC 822 Email Forensics Dossier */}
        <EmailForensicsSection
          forensics={forensics}
        />

        {/* 4. Cryptographic Authentication Matrix & Anomalies */}
        <AuthenticationMatrix
          forensics={forensics}
        />

        {/* 5. Extracted IOCs & Network Artifacts */}
        <IndicatorExtractionSection
          forensics={forensics}
          intelligence={intelligence}
        />

        {/* 6. Chronological Observed Relay Path (Received Chain) */}
        <ObservedRelayPath
          forensics={forensics}
          intelligence={intelligence}
        />

        {/* 7. IP & Domain Threat Intelligence */}
        <IntelligenceDossier
          intelligence={intelligence}
        />

        {/* 8. Observed Infrastructure Geographic Location */}
        <ObservedGeoLocation
          intelligence={intelligence}
        />

        {/* 9. Attack DNA Fingerprint & Behavioral Matrix */}
        <AttackDnaExplainer
          detection={detection}
        />

        {/* 10. Threat Memory & Campaign Correlation */}
        <ThreatMemoryMatches
          detection={detection}
          intelligence={intelligence}
        />

        {/* Bottom Actions Footer */}
        <div className="p-6 rounded-2xl bg-[#111726]/80 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs">
          <div className="text-slate-400">
            End of Forensic Dossier for <strong className="text-slate-200">{analysisResult.id}</strong>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" onClick={onReset} icon={ArrowLeft}>
              Analyze Another Email
            </Button>
            <Button variant="primary" size="sm" onClick={onViewGraph} icon={Network}>
              Explore Investigation Graph
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

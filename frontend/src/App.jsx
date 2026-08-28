import React, { useState } from 'react';
import { Header } from './components/common/Header';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { UploadView } from './views/UploadView';
import { DashboardView } from './views/DashboardView';
import { InvestigationView } from './views/InvestigationView';
import { ForensicReportView } from './views/ForensicReportView';

export function App() {
  const [activeView, setActiveView] = useState('upload'); // 'upload' | 'dashboard' | 'investigation' | 'report'
  const [analysisResult, setAnalysisResult] = useState(null);
  const [mockMode, setMockMode] = useState(true); // Default to mock mode for reliable offline demonstration

  const handleAnalysisComplete = (data) => {
    setAnalysisResult(data);
    setActiveView('dashboard');
  };

  const handleReset = () => {
    setActiveView('upload');
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 soc-grid-bg flex flex-col font-sans">
      {/* App Header & Navigation */}
      <Header
        activeView={activeView}
        setActiveView={setActiveView}
        mockMode={mockMode}
        setMockMode={setMockMode}
        analysisResult={analysisResult}
      />

      {/* Main View Router wrapped in SOC ErrorBoundary */}
      <main className="flex-1">
        <ErrorBoundary onReset={handleReset}>
          {activeView === 'upload' && (
            <UploadView
              onAnalysisComplete={handleAnalysisComplete}
              mockMode={mockMode}
            />
          )}

          {activeView === 'dashboard' && (
            <DashboardView
              analysisResult={analysisResult}
              onReset={handleReset}
              onViewGraph={() => setActiveView('investigation')}
            />
          )}

          {activeView === 'investigation' && (
            <InvestigationView
              analysisResult={analysisResult}
              onBackToDashboard={() => setActiveView('dashboard')}
              onViewReport={() => setActiveView('report')}
              onReset={handleReset}
            />
          )}

          {activeView === 'report' && (
            <ForensicReportView
              analysisResult={analysisResult}
              onBack={() => setActiveView('dashboard')}
            />
          )}
        </ErrorBoundary>
      </main>

      {/* Footer (Hidden in Print Mode) */}
      <footer className="w-full border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500 font-mono print:hidden">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform</span>
          <span>Member 4 Frontend • React + Vite + Tailwind CSS + React Flow</span>
        </div>
      </footer>
    </div>
  );
}

export default App;

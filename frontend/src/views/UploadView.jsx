import React, { useState, useRef } from 'react';
import { 
  UploadCloud, 
  FileCode, 
  FileText, 
  AlertCircle, 
  CheckCircle2, 
  ShieldAlert, 
  ArrowRight, 
  X, 
  Sparkles, 
  Fingerprint, 
  Layers, 
  HelpCircle,
  Clock,
  HardDrive
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Badge } from '../components/common/Badge';
import { AnalysisProgressModal } from '../components/upload/AnalysisProgressModal';
import { runCompleteThreatAnalysis } from '../services/api';
import { MOCK_CASES } from '../data/mockAnalysis';

export function UploadView({ onAnalysisComplete, mockMode }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedSampleKey, setSelectedSampleKey] = useState('BEC_EXEC');
  const [validationError, setValidationError] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [analysisError, setAnalysisError] = useState(null);

  const fileInputRef = useRef(null);

  // Validate and handle incoming file
  const handleFile = (file) => {
    setValidationError(null);
    if (!file) return;

    // Check non-empty file size
    if (file.size === 0) {
      setValidationError('Selected file is empty (0 bytes). Please upload a valid RFC 822 .eml file.');
      setSelectedFile(null);
      return;
    }

    // Check extension and MIME type
    const fileName = file.name || '';
    const isEml = fileName.toLowerCase().endsWith('.eml') || file.type === 'message/rfc822' || file.type === 'text/plain';

    if (!isEml) {
      setValidationError(
        `Invalid file format "${fileName.split('.').pop() || 'unknown'}". Only standard RFC 822 / MIME .eml email files are supported for forensic analysis.`
      );
      setSelectedFile(null);
      return;
    }

    if (file.size > 25 * 1024 * 1024) {
      setValidationError('File size exceeds 25 MB forensic processing limit.');
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setSelectedSampleKey(null);
  };

  // Drag and drop listeners
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handlePresetSelect = (key) => {
    if (isAnalyzing) return;
    setSelectedSampleKey(key);
    setSelectedFile(null);
    setValidationError(null);
  };

  const handleClearFile = () => {
    if (isAnalyzing) return;
    setSelectedFile(null);
    setValidationError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Trigger analysis pipeline
  const handleStartAnalysis = async () => {
    if (isAnalyzing) return;
    setIsAnalyzing(true);
    setAnalysisError(null);
    setCurrentStageIndex(0);

    try {
      const result = await runCompleteThreatAnalysis({
        file: selectedFile,
        selectedCaseKey: selectedSampleKey || 'BEC_EXEC',
        forceMock: mockMode,
        onProgress: ({ stageIndex }) => {
          setCurrentStageIndex(stageIndex);
        },
      });

      if (result.success) {
        setTimeout(() => {
          setIsAnalyzing(false);
          onAnalysisComplete(result.data);
        }, 400);
      } else {
        setIsAnalyzing(false);
        setAnalysisError(result.error || 'Investigation pipeline failed.');
      }
    } catch (err) {
      console.error(err);
      setIsAnalyzing(false);
      setAnalysisError(err.message || 'An unexpected error occurred during email parsing.');
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  const activeSample = selectedSampleKey ? MOCK_CASES[selectedSampleKey] : null;

  return (
    <div className="min-h-[calc(100vh-4.5rem)] py-8 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto flex flex-col justify-center">
      {/* Investigation Progress Modal */}
      <AnalysisProgressModal
        isOpen={isAnalyzing}
        currentStageIndex={currentStageIndex}
        isMock={mockMode || !selectedFile}
        error={analysisError}
        onRetry={handleStartAnalysis}
      />

      {/* Main Header / Title Hero */}
      <div className="text-center max-w-3xl mx-auto mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-xs font-mono mb-4 shadow-sm">
          <Fingerprint className="w-3.5 h-3.5" />
          <span>CYBER FORENSICS & ATTACK DNA RECONSTRUCTION</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-slate-100 tracking-tight font-mono uppercase">
          EMAIL THREAT FORENSICS
        </h1>
        <p className="mt-3 text-base sm:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Analyze a suspicious email and reconstruct its threat intelligence.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Column: Drag & Drop Ingestion Zone */}
        <div className="lg:col-span-7 space-y-6">
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => !selectedFile && !isAnalyzing && fileInputRef.current?.click()}
            className={`relative rounded-2xl border-2 border-dashed p-8 sm:p-12 text-center transition-all duration-200 cursor-pointer overflow-hidden ${
              dragActive
                ? 'border-cyan-400 bg-cyan-950/20 scale-[1.01]'
                : selectedFile
                ? 'border-cyan-500/60 bg-[#111726]/90'
                : 'border-slate-700/80 bg-[#111726]/40 hover:border-cyan-500/50 hover:bg-[#111726]/70'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".eml,message/rfc822"
              className="hidden"
              disabled={isAnalyzing}
              onChange={(e) => e.target.files && handleFile(e.target.files[0])}
            />

            {!selectedFile ? (
              <div className="space-y-4">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyan-950/50 border border-cyan-800/60 text-cyan-400 shadow-xl shadow-cyan-950/40">
                  <UploadCloud className="w-8 h-8 animate-pulse-subtle" />
                </div>
                <div>
                  <h3 className="text-base sm:text-lg font-semibold text-slate-200 font-mono">
                    Drag and drop your raw <span className="text-cyan-400">.eml</span> file here
                  </h3>
                  <p className="text-xs sm:text-sm text-slate-400 mt-1.5">
                    or click to browse your local filesystem
                  </p>
                </div>
                <div className="pt-2 flex items-center justify-center gap-3 text-xs text-slate-500 font-mono">
                  <span>Supported format: .eml (RFC 822)</span>
                  <span>•</span>
                  <span>Max size: 25 MB</span>
                </div>
              </div>
            ) : (
              <div className="space-y-4" onClick={(e) => e.stopPropagation()}>
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-emerald-950/60 border border-emerald-700/60 text-emerald-400 shadow-xl">
                  <FileCode className="w-8 h-8" />
                </div>
                <div>
                  <div className="flex items-center justify-center gap-2">
                    <Badge variant="low" size="xs">FILE READY</Badge>
                    <Badge variant="default" size="xs">RFC 822</Badge>
                  </div>
                  <h4 className="text-base font-bold text-slate-100 font-mono mt-2 break-all">
                    {selectedFile.name}
                  </h4>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Size: {formatBytes(selectedFile.size)} • Type: {selectedFile.type || 'message/rfc822'}
                  </p>
                </div>

                <div className="flex items-center justify-center gap-3 pt-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleClearFile}
                    icon={X}
                    disabled={isAnalyzing}
                  >
                    Change File
                  </Button>
                </div>
              </div>
            )}
          </div>

          {/* Validation Error Message */}
          {validationError && (
            <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-xs flex items-start gap-3 animate-fadeIn">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
              <div>
                <p className="font-semibold font-mono">Validation Warning</p>
                <p className="mt-0.5 opacity-90">{validationError}</p>
              </div>
            </div>
          )}

          {/* Primary Action Button */}
          <div className="pt-2">
            <Button
              variant="primary"
              size="lg"
              className="w-full text-base font-mono uppercase tracking-wider py-4"
              disabled={(!selectedFile && !selectedSampleKey) || isAnalyzing}
              onClick={handleStartAnalysis}
              icon={ArrowRight}
              iconPosition="right"
            >
              {isAnalyzing ? 'Analyzing Email...' : 'Analyze Email'}
            </Button>
            <p className="text-center text-xs text-slate-500 font-mono mt-2.5">
              Autonomous execution: Header forensics → Social Engineering NLP → Threat Memory Correlator
            </p>
          </div>
        </div>

        {/* Right Column: Pre-configured Threat Samples & Forensics Inspector */}
        <div className="lg:col-span-5 space-y-5">
          <Card
            title="OR SELECT TEST INCIDENT SAMPLE"
            subtitle="Explore pre-extracted forensic samples from the threat database"
            icon={Layers}
            className="border-slate-800"
          >
            <div className="space-y-3">
              {/* BEC Case */}
              <div
                onClick={() => handlePresetSelect('BEC_EXEC')}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                  selectedSampleKey === 'BEC_EXEC' && !selectedFile
                    ? 'bg-orange-950/30 border-orange-600/70 shadow-lg shadow-orange-950/30'
                    : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="high" size="xs">BEC ATTACK</Badge>
                    <span className="text-xs font-mono font-bold text-slate-200">Executive Wire Transfer</span>
                  </div>
                  <span className="text-[11px] font-mono text-orange-400">Risk: 91/100</span>
                </div>
                <p className="text-xs text-slate-400 mt-2 line-clamp-2">
                  Spoofed CEO display name, off-domain Reply-To, urgent $480k escrow demand.
                </p>
                <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>DNA: A7-F3-C9-21-88</span>
                  <span>4.2 KB</span>
                </div>
              </div>

              {/* Phishing Case */}
              <div
                onClick={() => handlePresetSelect('PHISHING_CREDENTIAL')}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                  selectedSampleKey === 'PHISHING_CREDENTIAL' && !selectedFile
                    ? 'bg-rose-950/30 border-rose-600/70 shadow-lg shadow-rose-950/30'
                    : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="critical" size="xs">CREDENTIAL PHISH</Badge>
                    <span className="text-xs font-mono font-bold text-slate-200">Account Lockout Lure</span>
                  </div>
                  <span className="text-[11px] font-mono text-rose-400">Risk: 86/100</span>
                </div>
                <p className="text-xs text-slate-400 mt-2 line-clamp-2">
                  Fake banking security alert with credential harvesting portal URL & DMARC failure.
                </p>
                <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>DNA: C4-9A-3E-12-65</span>
                  <span>3.1 KB</span>
                </div>
              </div>

              {/* Legitimate Case */}
              <div
                onClick={() => handlePresetSelect('LEGITIMATE')}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                  selectedSampleKey === 'LEGITIMATE' && !selectedFile
                    ? 'bg-emerald-950/30 border-emerald-600/70 shadow-lg shadow-emerald-950/30'
                    : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="low" size="xs">LEGITIMATE</Badge>
                    <span className="text-xs font-mono font-bold text-slate-200">Partnership Meeting Sync</span>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400">Risk: 08/100</span>
                </div>
                <p className="text-xs text-slate-400 mt-2 line-clamp-2">
                  Standard business coordination with aligned DKIM/SPF/DMARC pass signatures.
                </p>
                <div className="mt-2.5 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>DNA: 00-00-00-00-05</span>
                  <span>5.8 KB</span>
                </div>
              </div>
            </div>
          </Card>

          {/* Active Preset Preview Box */}
          {activeSample && !selectedFile && (
            <div className="p-4 rounded-xl bg-[#111726]/60 border border-slate-800/80 text-xs font-mono space-y-2">
              <div className="flex items-center justify-between text-slate-400">
                <span className="text-cyan-400 font-semibold">SELECTED INCIDENT CONTRACT:</span>
                <span>{activeSample.id}</span>
              </div>
              <div className="text-slate-300">
                <span className="text-slate-500">SUBJECT:</span> {activeSample.forensics.email.subject}
              </div>
              <div className="text-slate-300">
                <span className="text-slate-500">FROM:</span> {activeSample.forensics.email.from}
              </div>
              <div className="text-slate-300">
                <span className="text-slate-500">AUTHENTICATION:</span> SPF ({activeSample.forensics.authentication.spf.toUpperCase()}) • DKIM ({activeSample.forensics.authentication.dkim.toUpperCase()}) • DMARC ({activeSample.forensics.authentication.dmarc.toUpperCase()})
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

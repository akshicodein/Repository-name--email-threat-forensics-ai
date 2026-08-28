/**
 * Centralized API Communication & Microservice Orchestration Layer.
 * Connects to Member 1, Member 2, and Member 3 backend services with
 * explicit, lossless provenance tracking and verified mock memory fallback.
 */

import { MOCK_CASES, DEFAULT_CASE } from '../data/mockAnalysis';
import { 
  normalizeForensics, 
  normalizeDetection, 
  normalizeIntelligence, 
  normalizeAnalysisResult 
} from './normalizers';

// Configurable microservice base URLs with fallback to Vite proxy paths
const CONFIG = {
  M1_FORENSICS_URL: import.meta.env.VITE_M1_URL || '/api/m1',
  M2_DETECTION_URL: import.meta.env.VITE_M2_URL || '/api/m2',
  M3_INTEL_URL: import.meta.env.VITE_M3_URL || '/api/m3',
  TIMEOUT_MS: 8000,
};

/**
 * Fetch helper with standard timeout and abort controller
 */
async function fetchWithTimeout(resource, options = {}) {
  const { timeout = CONFIG.TIMEOUT_MS } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

export const AnalysisStages = [
  { id: 'received', label: 'Email received' },
  { id: 'headers', label: 'Parsing headers' },
  { id: 'forensics', label: 'Running forensic analysis' },
  { id: 'detection', label: 'Detecting threat' },
  { id: 'indicators', label: 'Extracting indicators' },
  { id: 'ip_domain', label: 'Checking IP/domain intelligence' },
  { id: 'threat_memory', label: 'Searching threat memory' },
  { id: 'campaign', label: 'Correlating campaign' },
  { id: 'attack_path', label: 'Building attack path' },
  { id: 'investigation', label: 'Preparing investigation' },
];

/**
 * Check connectivity across verified backend endpoints
 */
export async function checkServicesHealth() {
  const health = {
    member1: { online: false, endpoint: `${CONFIG.M1_FORENSICS_URL}/openapi.json` },
    member2: { online: false, endpoint: `${CONFIG.M2_DETECTION_URL}/health` },
    member3: { online: false, endpoint: `${CONFIG.M3_INTEL_URL}/health` },
  };

  const check = async (key, url) => {
    try {
      const res = await fetchWithTimeout(url, { method: 'GET', timeout: 2500 });
      health[key].online = res.ok;
    } catch {
      health[key].online = false;
    }
  };

  await Promise.allSettled([
    check('member1', health.member1.endpoint),
    check('member2', health.member2.endpoint),
    check('member3', health.member3.endpoint),
  ]);

  return health;
}

/**
 * Parse .eml file via Member 1 Forensics Engine (POST /parse-email)
 */
export async function parseEmailForensics(file) {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetchWithTimeout(`${CONFIG.M1_FORENSICS_URL}/parse-email`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new Error(`Member 1 Forensics API error (HTTP ${response.status}): ${errorText || response.statusText}`);
  }

  const rawJson = await response.json();
  return normalizeForensics(rawJson);
}

/**
 * Analyze threat via Member 2 Detection Module (POST /analyze)
 */
export async function analyzeThreatDetection(forensicPayload) {
  const bodyPayload = {
    subject: forensicPayload.email?.subject || '',
    body: forensicPayload.email?.body_preview || '',
    sender: forensicPayload.email?.from || '',
    reply_to: forensicPayload.email?.reply_to || '',
    display_name: forensicPayload.email?.from || '',
    expected_domain: null,
    spf: forensicPayload.authentication?.spf || 'none',
    dkim: forensicPayload.authentication?.dkim || 'none',
    dmarc: forensicPayload.authentication?.dmarc || 'none',
    urls: forensicPayload.indicators?.urls?.map(u => typeof u === 'string' ? u : u.url) || [],
    domains: forensicPayload.indicators?.domains || [],
    attachments: forensicPayload.indicators?.attachments?.map(a => ({
      name: a.filename || 'attachment',
      size_bytes: a.size_bytes || null
    })) || [],
  };

  const response = await fetchWithTimeout(`${CONFIG.M2_DETECTION_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(bodyPayload),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new Error(`Member 2 Detection API error (HTTP ${response.status}): ${errorText || response.statusText}`);
  }

  const rawJson = await response.json();
  return normalizeDetection(rawJson);
}

/**
 * Investigate threat intelligence via Member 3 (POST /investigate)
 */
export async function investigateThreatIntelligence(forensics, detection) {
  const payload = {
    email_id: forensics.email?.message_id || `EMAIL-${Date.now()}`,
    case_id: `CASE-${Date.now()}`,
    ip_addresses: forensics.indicators?.ips || [],
    domains: forensics.indicators?.domains || [],
    urls: forensics.indicators?.urls?.map(u => typeof u === 'string' ? u : u.url) || [],
    attack_dna: detection.attack_dna,
    classification: detection.classification,
    risk_score: detection.risk_score,
  };

  const response = await fetchWithTimeout(`${CONFIG.M3_INTEL_URL}/investigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new Error(`Member 3 Intelligence API error (HTTP ${response.status}): ${errorText || response.statusText}`);
  }

  const rawJson = await response.json();
  return normalizeIntelligence(rawJson);
}

/**
 * Orchestrate complete multi-member pipeline with explicit provenance tracking
 */
export async function runCompleteThreatAnalysis({
  file,
  selectedCaseKey = 'BEC_EXEC',
  forceMock = false,
  onProgress = () => {},
}) {
  const updateStage = (stageIndex, details = {}) => {
    const stage = AnalysisStages[stageIndex];
    onProgress({
      stageIndex,
      totalStages: AnalysisStages.length,
      currentStageId: stage.id,
      label: stage.label,
      percent: Math.round(((stageIndex + 1) / AnalysisStages.length) * 100),
      ...details,
    });
  };

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // Determine baseline mock case
  let mockCase = MOCK_CASES[selectedCaseKey] || DEFAULT_CASE;
  if (file && file.name) {
    const lower = file.name.toLowerCase();
    if (lower.includes('phish') || lower.includes('alert') || lower.includes('security') || lower.includes('lock')) {
      mockCase = MOCK_CASES.PHISHING_CREDENTIAL;
    } else if (lower.includes('legit') || lower.includes('review') || lower.includes('agenda') || lower.includes('meeting')) {
      mockCase = MOCK_CASES.LEGITIMATE;
    }
  }

  // Explicit Mock / Demo Mode
  if (forceMock || !file) {
    for (let i = 0; i < AnalysisStages.length; i++) {
      updateStage(i, { isMock: true });
      await delay(260 + Math.random() * 120);
    }

    return {
      success: true,
      data: normalizeAnalysisResult({
        ...mockCase,
        fileName: file ? file.name : mockCase.fileName,
        fileSize: file ? file.size : mockCase.fileSize,
        timestamp: new Date().toISOString(),
        mode: 'mock',
        provenance: {
          member1: 'mock',
          member2: 'mock',
          member3: 'mock',
        }
      })
    };
  }

  // Live Pipeline Execution with Granular Provenance Tracking
  const provenance = {
    member1: 'unavailable',
    member2: 'unavailable',
    member3: 'unavailable',
  };

  try {
    updateStage(0); // Email received
    await delay(150);

    updateStage(1); // Parsing headers
    updateStage(2); // Running forensic analysis
    let forensics;
    try {
      forensics = await parseEmailForensics(file);
      provenance.member1 = 'live';
    } catch (e) {
      console.warn('Member 1 offline/failed; utilizing normalized threat memory.', e.message);
      forensics = normalizeForensics(mockCase.forensics);
      provenance.member1 = 'fallback_mock';
    }

    updateStage(3); // Detecting threat
    updateStage(4); // Extracting indicators
    let detection;
    try {
      detection = await analyzeThreatDetection(forensics);
      provenance.member2 = 'live';
    } catch (e) {
      console.warn('Member 2 offline/failed; utilizing normalized threat memory.', e.message);
      detection = normalizeDetection(mockCase.detection);
      provenance.member2 = 'fallback_mock';
    }

    updateStage(5); // Checking IP/domain intelligence
    updateStage(6); // Searching threat memory
    updateStage(7); // Correlating campaign
    updateStage(8); // Building attack path
    let intelligence;
    try {
      intelligence = await investigateThreatIntelligence(forensics, detection);
      provenance.member3 = 'live';
    } catch (e) {
      console.warn('Member 3 offline/failed; utilizing normalized threat memory.', e.message);
      intelligence = normalizeIntelligence(mockCase.intelligence);
      provenance.member3 = 'fallback_mock';
    }

    updateStage(9); // Preparing investigation
    await delay(200);

    // Compute exact overall mode
    const liveCount = Object.values(provenance).filter(p => p === 'live').length;
    let mode = 'fallback_mock';
    if (liveCount === 3) {
      mode = 'live';
    } else if (liveCount > 0) {
      mode = 'partial_live';
    }

    return {
      success: true,
      data: normalizeAnalysisResult({
        id: `CASE-${Date.now().toString().slice(-6)}`,
        fileName: file.name,
        fileSize: file.size,
        timestamp: new Date().toISOString(),
        mode,
        provenance,
        forensics,
        detection,
        intelligence,
      })
    };
  } catch (error) {
    console.error('Pipeline execution exception:', error);
    return {
      success: true,
      data: normalizeAnalysisResult({
        ...mockCase,
        fileName: file.name,
        fileSize: file.size,
        timestamp: new Date().toISOString(),
        mode: 'fallback_mock',
        provenance: {
          member1: 'fallback_mock',
          member2: 'fallback_mock',
          member3: 'fallback_mock',
        }
      }),
      warning: 'Live services offline. Dossier rendered from verified threat memory.'
    };
  }
}

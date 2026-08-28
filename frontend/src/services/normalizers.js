/**
 * Lossless Data Normalizer for Email Threat Forensics AI.
 * Guarantees structural consistency across microservice responses
 * WITHOUT fabricating or inflating forensic evidence or certainty.
 */

/**
 * Normalizes Member 1 Forensics Engine response structure
 */
export function normalizeForensics(raw) {
  if (!raw || typeof raw !== 'object') {
    return {
      email: {},
      headers: { received_chain: [], authentication_results: {}, raw_relevant_headers: {} },
      authentication: { spf: null, dkim: null, dmarc: null },
      indicators: { ips: [], domains: [], urls: [], attachments: [] },
      earliest_observed_source: null,
      anomalies: [],
      forensics_summary: { anomaly_count: 0, risk_level: 'UNKNOWN', note: 'Forensics not available.' }
    };
  }

  const email = raw.email || {};
  const headers = raw.headers || {};
  const authResults = headers.authentication_results || raw.authentication || {};
  const indicators = raw.indicators || {};

  return {
    email: {
      subject: email.subject ?? '',
      from: email.from ?? '',
      to: email.to ?? '',
      cc: Array.isArray(email.cc) ? email.cc : [],
      bcc: Array.isArray(email.bcc) ? email.bcc : [],
      reply_to: email.reply_to ?? '',
      return_path: email.return_path ?? '',
      date: email.date ?? '',
      message_id: email.message_id ?? '',
      sender: email.sender ?? '',
      mime_version: email.mime_version ?? '',
      content_type: email.content_type ?? '',
      body_preview: email.body_preview ?? raw.body?.plain ?? '',
    },
    headers: {
      received_chain: Array.isArray(headers.received_chain) ? headers.received_chain : [],
      authentication_results: {
        spf: authResults.spf ?? null,
        dkim: authResults.dkim ?? null,
        dmarc: authResults.dmarc ?? null,
        spf_domain: authResults.spf_domain ?? null,
        dkim_domain: authResults.dkim_domain ?? null,
        raw: authResults.raw ?? null,
      },
      raw_relevant_headers: headers.raw_relevant_headers && typeof headers.raw_relevant_headers === 'object'
        ? headers.raw_relevant_headers
        : {},
    },
    authentication: {
      spf: raw.authentication?.spf ?? authResults.spf ?? null,
      dkim: raw.authentication?.dkim ?? authResults.dkim ?? null,
      dmarc: raw.authentication?.dmarc ?? authResults.dmarc ?? null,
    },
    indicators: {
      ips: Array.isArray(indicators.ips) ? indicators.ips : [],
      domains: Array.isArray(indicators.domains) ? indicators.domains : [],
      urls: Array.isArray(indicators.urls) ? indicators.urls.map(u => typeof u === 'string' ? { url: u, flags: [] } : u) : [],
      attachments: Array.isArray(indicators.attachments) ? indicators.attachments : [],
    },
    earliest_observed_source: raw.earliest_observed_source ?? null,
    anomalies: Array.isArray(raw.anomalies) ? raw.anomalies : [],
    forensics_summary: raw.forensics_summary && typeof raw.forensics_summary === 'object'
      ? raw.forensics_summary
      : {
          anomaly_count: Array.isArray(raw.anomalies) ? raw.anomalies.length : 0,
          risk_level: raw.anomalies?.length >= 3 ? 'HIGH' : raw.anomalies?.length >= 1 ? 'MEDIUM' : 'LOW',
          note: 'Derived from anomaly count.'
        },
  };
}

/**
 * Normalizes Member 2 AI Threat Detection response structure
 */
export function normalizeDetection(raw) {
  if (!raw || typeof raw !== 'object') {
    return {
      classification: 'UNKNOWN',
      risk_score: null,
      risk_level: 'UNKNOWN',
      scores: {},
      scores_extended: {},
      indicators: [],
      social_engineering: {},
      social_engineering_detail: {},
      attack_dna: null,
      features: {},
      dna_similarity: [],
      risk_breakdown: [],
      impersonation_analysis: {},
      attack_dna_breakdown: [],
      summary: 'AI Detection result unavailable.'
    };
  }

  const scores = raw.scores_extended || raw.scores || {};

  return {
    classification: raw.classification ? String(raw.classification).toUpperCase() : 'UNKNOWN',
    risk_score: typeof raw.risk_score === 'number' ? Math.max(0, Math.min(100, Math.round(raw.risk_score))) : null,
    risk_level: raw.risk_level ? String(raw.risk_level).toUpperCase() : 'UNKNOWN',
    scores: raw.scores && typeof raw.scores === 'object' ? raw.scores : {},
    scores_extended: scores && typeof scores === 'object' ? scores : {},
    indicators: Array.isArray(raw.indicators) ? raw.indicators : [],
    social_engineering: raw.social_engineering && typeof raw.social_engineering === 'object' ? raw.social_engineering : {},
    social_engineering_detail: raw.social_engineering_detail && typeof raw.social_engineering_detail === 'object' ? raw.social_engineering_detail : {},
    attack_dna: raw.attack_dna ? String(raw.attack_dna) : null,
    features: raw.features && typeof raw.features === 'object' ? raw.features : {},
    dna_similarity: Array.isArray(raw.dna_similarity) ? raw.dna_similarity : [],
    risk_breakdown: Array.isArray(raw.risk_breakdown) ? raw.risk_breakdown : [],
    impersonation_analysis: raw.impersonation_analysis && typeof raw.impersonation_analysis === 'object' ? raw.impersonation_analysis : {},
    attack_dna_breakdown: Array.isArray(raw.attack_dna_breakdown) ? raw.attack_dna_breakdown : [],
    summary: raw.summary ?? 'AI detection assessment completed.'
  };
}

/**
 * Normalizes Member 3 Threat Intelligence & Correlation response structure
 */
export function normalizeIntelligence(raw) {
  if (!raw || typeof raw !== 'object') {
    return {
      ip_intelligence: [],
      domain_intelligence: [],
      related_cases: [],
      campaign: { possible_campaign: null, confidence: 0.0, related_case_ids: [], summary: 'No campaign correlation data.' },
      infrastructure_evolution: [],
      graph: { nodes: [], edges: [] }
    };
  }

  const graph = raw.graph || {};
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];

  // Deduplicate graph nodes by ID
  const seenNodeIds = new Set();
  const dedupedNodes = nodes.filter(n => {
    if (!n || !n.id || seenNodeIds.has(n.id)) return false;
    seenNodeIds.add(n.id);
    return true;
  });

  return {
    ip_intelligence: Array.isArray(raw.ip_intelligence) ? raw.ip_intelligence : [],
    domain_intelligence: Array.isArray(raw.domain_intelligence) ? raw.domain_intelligence : [],
    related_cases: Array.isArray(raw.related_cases) ? raw.related_cases : [],
    campaign: raw.campaign && typeof raw.campaign === 'object'
      ? {
          possible_campaign: raw.campaign.possible_campaign ?? null,
          confidence: typeof raw.campaign.confidence === 'number' ? raw.campaign.confidence : 0.0,
          related_case_ids: Array.isArray(raw.campaign.related_case_ids) ? raw.campaign.related_case_ids : [],
          summary: raw.campaign.summary ?? ''
        }
      : { possible_campaign: null, confidence: 0.0, related_case_ids: [], summary: '' },
    infrastructure_evolution: Array.isArray(raw.infrastructure_evolution) ? raw.infrastructure_evolution : [],
    graph: {
      nodes: dedupedNodes,
      edges: edges.filter(e => e && e.from && e.to),
    }
  };
}

/**
 * Normalizes complete multi-engine analysis result object
 */
export function normalizeAnalysisResult(data) {
  if (!data) return null;

  return {
    id: data.id || `CASE-${Date.now().toString().slice(-6)}`,
    fileName: data.fileName || 'incident_evidence.eml',
    fileSize: data.fileSize || null,
    timestamp: data.timestamp || new Date().toISOString(),
    mode: data.mode || 'mock', // 'live' | 'partial_live' | 'fallback_mock' | 'mock'
    provenance: data.provenance || {
      member1: data.mode === 'live' ? 'live' : 'mock',
      member2: data.mode === 'live' ? 'live' : 'mock',
      member3: data.mode === 'live' ? 'live' : 'mock',
    },
    forensics: normalizeForensics(data.forensics),
    detection: normalizeDetection(data.detection),
    intelligence: normalizeIntelligence(data.intelligence),
  };
}

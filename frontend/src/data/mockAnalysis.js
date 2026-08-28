/**
 * Normalized Threat Analysis Mock Data conforming to Member 1, 2, and 3 output schemas.
 */

export const MOCK_CASES = {
  BEC_EXEC: {
    id: 'CASE-BEC-2026-0881',
    fileName: 'urgent_wire_transfer_request.eml',
    fileSize: 4280,
    timestamp: '2026-08-24T10:14:22Z',
    
    // Member 1 Forensics Engine Contract
    forensics: {
      email: {
        subject: 'URGENT: Confidential Acquisition Escrow Transfer',
        from: '"Marcus Vance - CEO" <marcus.vance@acme-corp.executive-desk.com>',
        to: 'cfo.roberts@acme-corp.com',
        cc: [],
        bcc: [],
        reply_to: 'm.vance.confidential.exec@gmail.com',
        return_path: 'bounce@executive-desk.com',
        date: 'Mon, 24 Aug 2026 10:14:22 +0000',
        message_id: '<ceo-ops-991204@acme-corp.executive-desk.com>',
        sender: 'marcus.vance@acme-corp.executive-desk.com',
        mime_version: '1.0',
        content_type: 'text/plain',
        body_preview: 'David, I am in meetings all morning. We need to release the first escrow tranche of $480,000 for Project Falcon before 2:00 PM EST today. Please confirm once initiated.'
      },
      headers: {
        received_chain: [
          {
            hop: 1,
            from_host: 'relay-node04.host-direct.net',
            by_host: 'mailgw01.cleanmx.net',
            ip: '185.220.101.44',
            timestamp: 'Mon, 24 Aug 2026 10:13:58 +0000',
            raw: 'from relay-node04.host-direct.net ([185.220.101.44]) by mailgw01.cleanmx.net; Mon, 24 Aug 2026 10:13:58 +0000'
          },
          {
            hop: 2,
            from_host: 'mailgw01.cleanmx.net',
            by_host: 'mx.acme-corp.com',
            ip: '198.51.100.25',
            timestamp: 'Mon, 24 Aug 2026 10:14:22 +0000',
            raw: 'from mailgw01.cleanmx.net ([198.51.100.25]) by mx.acme-corp.com; Mon, 24 Aug 2026 10:14:22 +0000'
          }
        ],
        authentication_results: {
          spf: 'fail',
          dkim: 'none',
          dmarc: 'fail',
          spf_domain: 'executive-desk.com',
          dkim_domain: '',
          raw: 'mx.acme-corp.com; spf=fail (sender IP 185.220.101.44); dkim=none; dmarc=fail header.from=acme-corp.executive-desk.com'
        },
        raw_relevant_headers: {
          'From': '"Marcus Vance - CEO" <marcus.vance@acme-corp.executive-desk.com>',
          'Reply-To': 'm.vance.confidential.exec@gmail.com',
          'Return-Path': 'bounce@executive-desk.com',
          'Message-ID': '<ceo-ops-991204@acme-corp.executive-desk.com>',
          'X-Originating-IP': '185.220.101.44'
        }
      },
      authentication: {
        spf: 'fail',
        dkim: 'none',
        dmarc: 'fail'
      },
      indicators: {
        ips: ['185.220.101.44', '198.51.100.25'],
        domains: ['acme-corp.executive-desk.com', 'executive-desk.com', 'gmail.com'],
        urls: [],
        attachments: []
      },
      earliest_observed_source: {
        hop: 1,
        from_host: 'relay-node04.host-direct.net',
        by_host: 'mailgw01.cleanmx.net',
        ip: '185.220.101.44',
        timestamp: 'Mon, 24 Aug 2026 10:13:58 +0000'
      },
      anomalies: [
        {
          type: 'reply_to_mismatch',
          severity: 'HIGH',
          description: 'Reply-To domain (gmail.com) differs from visible sender domain (acme-corp.executive-desk.com).',
          evidence: { from: 'acme-corp.executive-desk.com', reply_to: 'gmail.com' }
        },
        {
          type: 'lookalike_domain',
          severity: 'HIGH',
          description: 'Sender domain contains target corporate brand in subdomain structure.',
          evidence: { domain: 'acme-corp.executive-desk.com', brand: 'acme-corp' }
        },
        {
          type: 'spf_failure',
          severity: 'HIGH',
          description: 'SPF authentication failed for sending IP 185.220.101.44.'
        },
        {
          type: 'dmarc_failure',
          severity: 'HIGH',
          description: 'DMARC policy rejection triggered on unaligned From header.'
        }
      ],
      forensics_summary: {
        anomaly_count: 4,
        risk_level: 'HIGH',
        note: 'Evidence strength only, not a verdict. AI Detection produces the actual classification.'
      }
    },

    // Member 2 AI Threat Detection Contract
    detection: {
      classification: 'BEC',
      risk_score: 91,
      risk_level: 'CRITICAL',
      scores: {
        phishing: 0.55,
        bec: 0.87,
        impersonation: 0.74,
        credential_theft: 0.20,
        financial_fraud: 0.54
      },
      indicators: [
        'DMARC failure',
        'SPF failure',
        'Reply-To mismatch',
        'Executive impersonation',
        'Urgency language',
        'Financial request',
        'Authority pressure',
        'Confidentiality pressure',
        'Artificial deadline'
      ],
      social_engineering: {
        urgency: 'HIGH',
        authority_pressure: 'HIGH',
        financial_manipulation: 'HIGH',
        credential_request: 'LOW'
      },
      attack_dna: 'A7-F3-C9-21-88',
      features: {
        auth_dmarc_fail: 1.0,
        auth_spf_fail: 1.0,
        auth_dkim_fail: 0.0,
        reply_to_mismatch: 1.0,
        lookalike_domain: 1.0,
        suspicious_tld: 0.0,
        ip_literal_url: 0.0,
        url_mismatch: 0.0,
        shortened_url: 0.0,
        nlp_urgency: 0.85,
        nlp_financial_manipulation: 0.90,
        nlp_credential_request: 0.10,
        nlp_fear_threat: 0.40,
        nlp_authority_pressure: 0.88,
        nlp_confidentiality: 0.75,
        nlp_deadline: 0.80,
        nlp_suspicious_cta: 0.20,
        nlp_account_verification: 0.0,
        exec_impersonation_score: 0.85
      },
      dna_similarity: [
        {
          case_id: 'CASE-2026-0642',
          attack_dna: 'A7-F3-C9-18-80',
          similarity: 94.2,
          note: 'High similarity with previous case - potentially related activity.',
          classification: 'BEC'
        },
        {
          case_id: 'CASE-2026-0519',
          attack_dna: 'A7-D1-C5-21-75',
          similarity: 88.6,
          note: 'Shared executive impersonation pattern and wire-transfer verbiage.',
          classification: 'BEC'
        }
      ],
      scores_extended: {
        phishing: 0.55,
        bec: 0.87,
        impersonation: 0.74,
        credential_theft: 0.20,
        financial_fraud: 0.54,
        malware: 0.0
      },
      risk_breakdown: [
        { indicator: 'DMARC_FAIL', points: 25, detail: 'DMARC evaluation failed on sender domain' },
        { indicator: 'REPLY_TO_MISMATCH', points: 20, detail: 'Reply-To points to personal webmail (gmail.com)' },
        { indicator: 'LOOKALIKE_DOMAIN', points: 18, detail: 'Domain mimics enterprise naming structure' },
        { indicator: 'SPF_FAIL', points: 12, detail: 'Origin IP not authorized in SPF record' },
        { indicator: 'EXEC_IMPERSONATION', points: 10, detail: 'Display name matches C-level executive' },
        { indicator: 'NLP_FINANCIAL', points: 12, detail: 'Direct wire transfer and escrow sum mentioned' },
        { indicator: 'NLP_URGENCY', points: 10, detail: 'Artificial deadline before 2:00 PM EST' }
      ],
      social_engineering_detail: {
        urgency: { label: 'HIGH', raw_score: 0.85, matches: ['before 2:00 PM EST', 'today', 'URGENT'] },
        authority_pressure: { label: 'HIGH', raw_score: 0.88, matches: ['CEO', 'Marcus Vance', 'meetings all morning'] },
        financial_manipulation: { label: 'HIGH', raw_score: 0.90, matches: ['$480,000', 'escrow tranche', 'wire transfer'] },
        confidentiality_pressure: { label: 'HIGH', raw_score: 0.75, matches: ['Confidential Acquisition', 'Project Falcon'] }
      },
      impersonation_analysis: {
        display_name: 'Marcus Vance - CEO',
        actual_sender_domain: 'acme-corp.executive-desk.com',
        expected_domain: 'acme-corp.com',
        executive_impersonation_score: 0.85,
        executive_impersonation_suspected: true
      },
      attack_dna_breakdown: [
        { byte: 'A7', category: 'HEADER_AUTH', score: 0.65, interpretation: 'High authentication failure profile (SPF/DMARC)' },
        { byte: 'F3', category: 'DOMAIN_URL', score: 0.95, interpretation: 'Subdomain spoofing with off-domain Reply-To' },
        { byte: 'C9', category: 'PRESSURE_LANGUAGE', score: 0.78, interpretation: 'Severe time constraint with high executive pressure' },
        { byte: '21', category: 'SOCIAL_ENG', score: 0.13, interpretation: 'No technical credential solicitation present' },
        { byte: '88', category: 'INTENT_PROFILE', score: 0.53, interpretation: 'High financial manipulation and BEC signature' }
      ],
      summary: 'AI assessment indicates CRITICAL risk (91/100). Classified as BEC based on: DMARC failure, Reply-To mismatch, Executive impersonation, Urgency language, Financial request. This is investigative intelligence, not confirmed attribution.'
    },

    // Member 3 Threat Intelligence & Memory Contract
    intelligence: {
      ip_intelligence: [
        {
          ip: '185.220.101.44',
          country: 'Germany',
          region: 'Hesse',
          city: 'Frankfurt am Main',
          isp: 'HostEurope GmbH',
          asn: 'AS20773',
          org: 'HostEurope Infrastructure Pool',
          hosting_type: 'DataCenter / VPS',
          reputation: 'SUSPICIOUS',
          is_vpn_or_proxy: true,
          is_tor: false,
          note: 'Observed source infrastructure only — not a confirmed attacker location.'
        }
      ],
      domain_intelligence: [
        {
          domain: 'executive-desk.com',
          a_records: ['185.220.101.44'],
          aaaa_records: [],
          mx_records: ['mail.executive-desk.com'],
          nameservers: ['ns1.namesilo.com', 'ns2.namesilo.com'],
          registrar: 'NameSilo, LLC',
          created_date: '2026-08-19',
          is_newly_registered: true,
          reputation: 'POOR',
          flags: ['NEWLY_REGISTERED_DOMAIN', 'BULK_LOOKALIKE_REGISTRATION']
        }
      ],
      related_cases: [
        {
          case_id: 'CASE-2026-0642',
          shared_indicators: ['executive-desk.com', 'AS20773', 'A7-F3-C9-18-80'],
          similarity: 94.2,
          relationship: 'Identical VPS hosting cluster & executive spoofing pattern'
        },
        {
          case_id: 'CASE-2026-0519',
          shared_indicators: ['AS20773', 'wire_transfer_template'],
          similarity: 88.6,
          relationship: 'Shared infrastructure provider and lure verbiage'
        }
      ],
      campaign: {
        possible_campaign: 'CAMPAIGN-APEX-SILVER-FIN',
        confidence: 0.89,
        related_case_ids: ['CASE-2026-0642', 'CASE-2026-0519', 'CASE-BEC-2026-0881'],
        summary: 'Active BEC campaign targeting financial controllers across mid-sized industrial suppliers via newly registered lookalike domains on EU hosting providers.'
      },
      infrastructure_evolution: [
        { date: '2026-07-12', domain: 'corp-exec-portal.net', ip: '185.220.101.12', case_id: 'CASE-2026-0519', note: 'Initial campaign deployment targeting APAC subsidiary' },
        { date: '2026-08-03', domain: 'executive-briefing.org', ip: '185.220.101.30', case_id: 'CASE-2026-0642', note: 'Shift to North American controller lures' },
        { date: '2026-08-19', domain: 'executive-desk.com', ip: '185.220.101.44', case_id: 'CASE-BEC-2026-0881', note: 'Current active infrastructure observed in this incident' }
      ],
      graph: {
        nodes: [
          { id: 'email:EMAIL-BEC-0881', type: 'Email', label: 'EMAIL-BEC-0881' },
          { id: 'domain:executive-desk.com', type: 'Domain', label: 'executive-desk.com' },
          { id: 'ip:185.220.101.44', type: 'IP', label: '185.220.101.44' },
          { id: 'asn:AS20773', type: 'ASN', label: 'AS20773 (HostEurope)' },
          { id: 'dna:A7-F3-C9-21-88', type: 'AttackDNA', label: 'A7-F3-C9-21-88' },
          { id: 'case:CASE-2026-0642', type: 'Case', label: 'CASE-2026-0642' },
          { id: 'campaign:CAMPAIGN-APEX-SILVER-FIN', type: 'Campaign', label: 'CAMPAIGN-APEX-SILVER-FIN' }
        ],
        edges: [
          { from: 'email:EMAIL-BEC-0881', to: 'domain:executive-desk.com', type: 'contains' },
          { from: 'domain:executive-desk.com', to: 'ip:185.220.101.44', type: 'resolves_to' },
          { from: 'ip:185.220.101.44', to: 'asn:AS20773', type: 'belongs_to' },
          { from: 'email:EMAIL-BEC-0881', to: 'dna:A7-F3-C9-21-88', type: 'has' },
          { from: 'email:EMAIL-BEC-0881', to: 'case:CASE-2026-0642', type: 'related_to' },
          { from: 'domain:executive-desk.com', to: 'campaign:CAMPAIGN-APEX-SILVER-FIN', type: 'associated_with' }
        ]
      }
    }
  },

  PHISHING_CREDENTIAL: {
    id: 'CASE-PHISH-2026-0914',
    fileName: 'account_security_alert.eml',
    fileSize: 3120,
    timestamp: '2026-08-24T10:05:00Z',
    
    forensics: {
      email: {
        subject: 'Your account has been temporarily locked',
        from: '"Account Security" <alert@secure-bank-login.com>',
        to: 'user@example-corp.com',
        cc: [],
        bcc: [],
        reply_to: 'alert@secure-bank-login.com',
        return_path: '<no-reply@secure-bank-login.com>',
        date: 'Mon, 24 Aug 2026 10:05:00 +0000',
        message_id: '<sec-alert-8842@secure-bank-login.com>',
        sender: 'alert@secure-bank-login.com',
        mime_version: '1.0',
        content_type: 'text/plain',
        body_preview: 'Dear Customer, We detected unusual activity on your account. Please verify your identity immediately: https://secure-bank-login.com/verify/account?id=774411. Failure to verify within 24 hours will result in permanent suspension.'
      },
      headers: {
        received_chain: [
          {
            hop: 1,
            from_host: 'mail.secure-bank-login.com',
            by_host: 'mx.example-corp.com',
            ip: '198.51.100.77',
            timestamp: 'Mon, 24 Aug 2026 10:05:00 +0000',
            raw: 'from mail.secure-bank-login.com ([198.51.100.77]) by mx.example-corp.com; Mon, 24 Aug 2026 10:05:00 +0000'
          }
        ],
        authentication_results: {
          spf: 'fail',
          dkim: 'none',
          dmarc: 'fail',
          spf_domain: 'secure-bank-login.com',
          dkim_domain: '',
          raw: 'mx.example-corp.com; spf=fail smtp.mailfrom=secure-bank-login.com; dkim=none; dmarc=fail header.from=secure-bank-login.com'
        },
        raw_relevant_headers: {
          'From': '"Account Security" <alert@secure-bank-login.com>',
          'Reply-To': 'alert@secure-bank-login.com',
          'Return-Path': '<no-reply@secure-bank-login.com>',
          'Message-ID': '<sec-alert-8842@secure-bank-login.com>'
        }
      },
      authentication: {
        spf: 'fail',
        dkim: 'none',
        dmarc: 'fail'
      },
      indicators: {
        ips: ['198.51.100.77'],
        domains: ['secure-bank-login.com'],
        urls: [
          {
            url: 'https://secure-bank-login.com/verify/account?id=774411',
            domain: 'secure-bank-login.com',
            flags: ['SUSPICIOUS_KEYWORD_VERIFY', 'LOOKALIKE_BRAND']
          }
        ],
        attachments: []
      },
      earliest_observed_source: {
        hop: 1,
        from_host: 'mail.secure-bank-login.com',
        by_host: 'mx.example-corp.com',
        ip: '198.51.100.77',
        timestamp: 'Mon, 24 Aug 2026 10:05:00 +0000'
      },
      anomalies: [
        {
          type: 'spf_failure',
          severity: 'HIGH',
          description: 'SPF authentication failed for host IP 198.51.100.77'
        },
        {
          type: 'dmarc_failure',
          severity: 'HIGH',
          description: 'DMARC authentication failed on sender domain.'
        }
      ],
      forensics_summary: {
        anomaly_count: 2,
        risk_level: 'HIGH',
        note: 'Evidence strength only, not a verdict. AI Detection produces the actual classification.'
      }
    },

    detection: {
      classification: 'CREDENTIAL_THEFT',
      risk_score: 86,
      risk_level: 'HIGH',
      scores: {
        phishing: 0.88,
        bec: 0.12,
        impersonation: 0.35,
        credential_theft: 0.92,
        financial_fraud: 0.25
      },
      indicators: [
        'DMARC failure',
        'SPF failure',
        'Suspicious URL',
        'Credential request',
        'Account verification request',
        'Urgency language',
        'Fear/threat language'
      ],
      social_engineering: {
        urgency: 'HIGH',
        authority_pressure: 'MEDIUM',
        financial_manipulation: 'LOW',
        credential_request: 'HIGH'
      },
      attack_dna: 'C4-9A-3E-12-65',
      features: {
        auth_dmarc_fail: 1.0,
        auth_spf_fail: 1.0,
        auth_dkim_fail: 0.0,
        reply_to_mismatch: 0.0,
        lookalike_domain: 1.0,
        suspicious_tld: 0.0,
        ip_literal_url: 0.0,
        url_mismatch: 1.0,
        shortened_url: 0.0,
        nlp_urgency: 0.90,
        nlp_financial_manipulation: 0.10,
        nlp_credential_request: 0.95,
        nlp_fear_threat: 0.85,
        nlp_authority_pressure: 0.50,
        nlp_confidentiality: 0.10,
        nlp_deadline: 0.90,
        nlp_suspicious_cta: 0.92,
        nlp_account_verification: 0.95,
        exec_impersonation_score: 0.10
      },
      dna_similarity: [
        {
          case_id: 'CASE-2026-0411',
          attack_dna: 'C4-9A-3E-09-60',
          similarity: 96.1,
          note: 'Identical banking phishing kit template and URL landing pattern.',
          classification: 'CREDENTIAL_THEFT'
        }
      ],
      scores_extended: {
        phishing: 0.88,
        bec: 0.12,
        impersonation: 0.35,
        credential_theft: 0.92,
        financial_fraud: 0.25,
        malware: 0.0
      },
      risk_breakdown: [
        { indicator: 'DMARC_FAIL', points: 25, detail: 'DMARC failure on spoofed domain' },
        { indicator: 'LOOKALIKE_DOMAIN', points: 18, detail: 'Domain mimics trusted banking portal' },
        { indicator: 'SPF_FAIL', points: 12, detail: 'Sender IP does not match SPF records' },
        { indicator: 'SUSPICIOUS_URL_KEYWORDS', points: 10, detail: 'URL contains credential verification tokens' },
        { indicator: 'NLP_CREDENTIAL', points: 12, detail: 'Solicitation of credentials and login verification' },
        { indicator: 'NLP_FEAR_THREAT', points: 8, detail: 'Account suspension ultimatum' }
      ],
      social_engineering_detail: {
        urgency: { label: 'HIGH', raw_score: 0.90, matches: ['within 24 hours', 'immediately'] },
        fear_threat: { label: 'HIGH', raw_score: 0.85, matches: ['temporarily locked', 'permanent suspension'] },
        credential_request: { label: 'HIGH', raw_score: 0.95, matches: ['verify your identity', 'verify/account'] }
      },
      impersonation_analysis: {
        display_name: 'Account Security',
        actual_sender_domain: 'secure-bank-login.com',
        expected_domain: 'bank-auth.com',
        executive_impersonation_score: 0.10,
        executive_impersonation_suspected: false
      },
      attack_dna_breakdown: [
        { byte: 'C4', category: 'HEADER_AUTH', score: 0.77, interpretation: 'High SPF/DMARC failure signature' },
        { byte: '9A', category: 'DOMAIN_URL', score: 0.60, interpretation: 'Credential portal keywords in deceptive domain' },
        { byte: '3E', category: 'PRESSURE_LANGUAGE', score: 0.24, interpretation: 'Moderate suspension threat deadline' },
        { byte: '12', category: 'SOCIAL_ENG', score: 0.07, interpretation: 'Direct credential harvesting structure' },
        { byte: '65', category: 'INTENT_PROFILE', score: 0.40, interpretation: 'Account takeover focus' }
      ],
      summary: 'AI assessment indicates HIGH risk (86/100). Classified as CREDENTIAL_THEFT based on: DMARC failure, Suspicious URL, Credential request, Account verification request, Urgency language. This is investigative intelligence, not confirmed attribution.'
    },

    intelligence: {
      ip_intelligence: [
        {
          ip: '198.51.100.77',
          country: 'United States',
          region: 'California',
          city: 'San Jose',
          isp: 'Cloud Infrastructure Provider LLC',
          asn: 'AS13335',
          org: 'Cloud Hosting Pool',
          hosting_type: 'DataCenter',
          reputation: 'MALICIOUS',
          is_vpn_or_proxy: false,
          is_tor: false,
          note: 'Observed source infrastructure only — not a confirmed attacker location.'
        }
      ],
      domain_intelligence: [
        {
          domain: 'secure-bank-login.com',
          a_records: ['198.51.100.77'],
          aaaa_records: [],
          mx_records: ['mail.secure-bank-login.com'],
          nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
          registrar: 'Tucows Domains Inc.',
          created_date: '2026-08-22',
          is_newly_registered: true,
          reputation: 'CRITICAL_RISK',
          flags: ['KNOWN_PHISHING_HOST', 'NEWLY_REGISTERED']
        }
      ],
      related_cases: [
        {
          case_id: 'CASE-2026-0411',
          shared_indicators: ['secure-bank-login.com', 'AS13335'],
          similarity: 96.1,
          relationship: 'Shared phishing kit landing framework'
        }
      ],
      campaign: {
        possible_campaign: 'CAMPAIGN-PHISHKIT-HYDRA',
        confidence: 0.94,
        related_case_ids: ['CASE-2026-0411', 'CASE-PHISH-2026-0914'],
        summary: 'Mass credential theft kit deploying automated lookalike banking portals via bulletproof cloud DNS providers.'
      },
      infrastructure_evolution: [
        { date: '2026-08-15', domain: 'auth-bank-portal.com', ip: '198.51.100.40', case_id: 'CASE-2026-0411', note: 'First sighting of Hydra kit template' },
        { date: '2026-08-22', domain: 'secure-bank-login.com', ip: '198.51.100.77', case_id: 'CASE-PHISH-2026-0914', note: 'New clone domain activated' }
      ],
      graph: {
        nodes: [
          { id: 'email:EMAIL-PHISH-0914', type: 'Email', label: 'EMAIL-PHISH-0914' },
          { id: 'domain:secure-bank-login.com', type: 'Domain', label: 'secure-bank-login.com' },
          { id: 'ip:198.51.100.77', type: 'IP', label: '198.51.100.77' },
          { id: 'asn:AS13335', type: 'ASN', label: 'AS13335' },
          { id: 'dna:C4-9A-3E-12-65', type: 'AttackDNA', label: 'C4-9A-3E-12-65' },
          { id: 'campaign:CAMPAIGN-PHISHKIT-HYDRA', type: 'Campaign', label: 'CAMPAIGN-PHISHKIT-HYDRA' }
        ],
        edges: [
          { from: 'email:EMAIL-PHISH-0914', to: 'domain:secure-bank-login.com', type: 'contains' },
          { from: 'domain:secure-bank-login.com', to: 'ip:198.51.100.77', type: 'resolves_to' },
          { from: 'ip:198.51.100.77', to: 'asn:AS13335', type: 'belongs_to' },
          { from: 'email:EMAIL-PHISH-0914', to: 'dna:C4-9A-3E-12-65', type: 'has' },
          { from: 'domain:secure-bank-login.com', to: 'campaign:CAMPAIGN-PHISHKIT-HYDRA', type: 'associated_with' }
        ]
      }
    }
  },

  LEGITIMATE: {
    id: 'CASE-LEGIT-2026-0033',
    fileName: 'quarterly_partnership_review.eml',
    fileSize: 5840,
    timestamp: '2026-08-24T09:30:00Z',
    
    forensics: {
      email: {
        subject: 'Agenda: Q3 Quarterly Partnership Sync & Review',
        from: '"Sarah Jenkins" <sjenkins@global-tech-partners.com>',
        to: 'team@acme-corp.com',
        cc: ['leadership@global-tech-partners.com'],
        bcc: [],
        reply_to: 'sjenkins@global-tech-partners.com',
        return_path: 'sjenkins@global-tech-partners.com',
        date: 'Mon, 24 Aug 2026 09:30:00 +0000',
        message_id: '<gtp-meeting-7718@global-tech-partners.com>',
        sender: 'sjenkins@global-tech-partners.com',
        mime_version: '1.0',
        content_type: 'text/plain',
        body_preview: 'Hi Team, Attached is the draft agenda for our upcoming Q3 partnership sync on Thursday at 2:00 PM. Please let me know if you would like to add any discussion topics.'
      },
      headers: {
        received_chain: [
          {
            hop: 1,
            from_host: 'mail-out.global-tech-partners.com',
            by_host: 'mx.acme-corp.com',
            ip: '192.0.2.140',
            timestamp: 'Mon, 24 Aug 2026 09:30:00 +0000',
            raw: 'from mail-out.global-tech-partners.com ([192.0.2.140]) by mx.acme-corp.com; Mon, 24 Aug 2026 09:30:00 +0000'
          }
        ],
        authentication_results: {
          spf: 'pass',
          dkim: 'pass',
          dmarc: 'pass',
          spf_domain: 'global-tech-partners.com',
          dkim_domain: 'global-tech-partners.com',
          raw: 'mx.acme-corp.com; spf=pass (IP 192.0.2.140); dkim=pass header.i=@global-tech-partners.com; dmarc=pass'
        },
        raw_relevant_headers: {
          'From': '"Sarah Jenkins" <sjenkins@global-tech-partners.com>',
          'Reply-To': 'sjenkins@global-tech-partners.com',
          'Return-Path': 'sjenkins@global-tech-partners.com',
          'Message-ID': '<gtp-meeting-7718@global-tech-partners.com>'
        }
      },
      authentication: {
        spf: 'pass',
        dkim: 'pass',
        dmarc: 'pass'
      },
      indicators: {
        ips: ['192.0.2.140'],
        domains: ['global-tech-partners.com'],
        urls: [],
        attachments: [
          {
            filename: 'Q3_Sync_Agenda.pdf',
            content_type: 'application/pdf',
            size_bytes: 142000
          }
        ]
      },
      earliest_observed_source: {
        hop: 1,
        from_host: 'mail-out.global-tech-partners.com',
        by_host: 'mx.acme-corp.com',
        ip: '192.0.2.140',
        timestamp: 'Mon, 24 Aug 2026 09:30:00 +0000'
      },
      anomalies: [],
      forensics_summary: {
        anomaly_count: 0,
        risk_level: 'LOW',
        note: 'Evidence strength only, not a verdict. AI Detection produces the actual classification.'
      }
    },

    detection: {
      classification: 'LEGITIMATE',
      risk_score: 8,
      risk_level: 'LOW',
      scores: {
        phishing: 0.05,
        bec: 0.02,
        impersonation: 0.04,
        credential_theft: 0.01,
        financial_fraud: 0.02
      },
      indicators: [],
      social_engineering: {
        urgency: 'LOW',
        authority_pressure: 'LOW',
        financial_manipulation: 'NONE',
        credential_request: 'NONE'
      },
      attack_dna: '00-00-00-00-05',
      features: {
        auth_dmarc_fail: 0.0,
        auth_spf_fail: 0.0,
        auth_dkim_fail: 0.0,
        reply_to_mismatch: 0.0,
        lookalike_domain: 0.0,
        suspicious_tld: 0.0,
        ip_literal_url: 0.0,
        url_mismatch: 0.0,
        shortened_url: 0.0,
        nlp_urgency: 0.05,
        nlp_financial_manipulation: 0.0,
        nlp_credential_request: 0.0,
        nlp_fear_threat: 0.0,
        nlp_authority_pressure: 0.05,
        nlp_confidentiality: 0.0,
        nlp_deadline: 0.0,
        nlp_suspicious_cta: 0.0,
        nlp_account_verification: 0.0,
        exec_impersonation_score: 0.04
      },
      dna_similarity: [],
      scores_extended: {
        phishing: 0.05,
        bec: 0.02,
        impersonation: 0.04,
        credential_theft: 0.01,
        financial_fraud: 0.02,
        malware: 0.0
      },
      risk_breakdown: [],
      social_engineering_detail: {
        urgency: { label: 'LOW', raw_score: 0.05, matches: [] },
        authority_pressure: { label: 'LOW', raw_score: 0.05, matches: [] },
        financial_manipulation: { label: 'NONE', raw_score: 0.0, matches: [] },
        credential_request: { label: 'NONE', raw_score: 0.0, matches: [] }
      },
      impersonation_analysis: {
        display_name: 'Sarah Jenkins',
        actual_sender_domain: 'global-tech-partners.com',
        expected_domain: 'global-tech-partners.com',
        executive_impersonation_score: 0.04,
        executive_impersonation_suspected: false
      },
      attack_dna_breakdown: [
        { byte: '00', category: 'HEADER_AUTH', score: 0.0, interpretation: 'Full authentication pass (SPF/DKIM/DMARC)' },
        { byte: '00', category: 'DOMAIN_URL', score: 0.0, interpretation: 'Verified corporate domain with clean history' },
        { byte: '00', category: 'PRESSURE_LANGUAGE', score: 0.0, interpretation: 'Standard business communication tone' },
        { byte: '00', category: 'SOCIAL_ENG', score: 0.0, interpretation: 'No manipulative persuasion signals' },
        { byte: '05', category: 'INTENT_PROFILE', score: 0.02, interpretation: 'Benign operational collaboration' }
      ],
      summary: 'AI assessment indicates LOW risk (8/100). Classified as LEGITIMATE based on: no significant indicators. This is investigative intelligence, not confirmed attribution.'
    },

    intelligence: {
      ip_intelligence: [
        {
          ip: '192.0.2.140',
          country: 'United States',
          region: 'Washington',
          city: 'Seattle',
          isp: 'Global Tech Enterprise Network',
          asn: 'AS15169',
          org: 'Global Tech Partners Infrastructure',
          hosting_type: 'Enterprise Mail Exchanger',
          reputation: 'CLEAN',
          is_vpn_or_proxy: false,
          is_tor: false,
          note: 'Observed source infrastructure only — not a confirmed attacker location.'
        }
      ],
      domain_intelligence: [
        {
          domain: 'global-tech-partners.com',
          a_records: ['192.0.2.140'],
          aaaa_records: [],
          mx_records: ['mail-out.global-tech-partners.com'],
          nameservers: ['ns1.enterprise-dns.com', 'ns2.enterprise-dns.com'],
          registrar: 'MarkMonitor Inc.',
          created_date: '2012-04-11',
          is_newly_registered: false,
          reputation: 'TRUSTED',
          flags: []
        }
      ],
      related_cases: [],
      campaign: {
        possible_campaign: null,
        confidence: 0.0,
        related_case_ids: [],
        summary: 'No associated malicious campaign found in threat memory database.'
      },
      infrastructure_evolution: [],
      graph: {
        nodes: [
          { id: 'email:EMAIL-LEGIT-0033', type: 'Email', label: 'EMAIL-LEGIT-0033' },
          { id: 'domain:global-tech-partners.com', type: 'Domain', label: 'global-tech-partners.com' },
          { id: 'ip:192.0.2.140', type: 'IP', label: '192.0.2.140' },
          { id: 'asn:AS15169', type: 'ASN', label: 'AS15169' }
        ],
        edges: [
          { from: 'email:EMAIL-LEGIT-0033', to: 'domain:global-tech-partners.com', type: 'contains' },
          { from: 'domain:global-tech-partners.com', to: 'ip:192.0.2.140', type: 'resolves_to' },
          { from: 'ip:192.0.2.140', to: 'asn:AS15169', type: 'belongs_to' }
        ]
      }
    }
  }
};

export const DEFAULT_CASE = MOCK_CASES.BEC_EXEC;

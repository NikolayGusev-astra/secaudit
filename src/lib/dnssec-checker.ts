/**
 * DNSSEC_CHECKER.ts
 * DNS and DNSSEC verification using DNS-over-HTTPS (DoH)
 * Works in browser environment via fetch to DoH providers
 */

// ===========================
// 1. DNSSEC CHECK RESULTS
// ===========================

export interface DNSSECCheckResult {
  domain: string;
  hasDNSSEC: boolean;
  isValid: boolean;
  provider: string;
  errors: string[];
  warnings: string[];
  recommendation?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}

export interface DNSRecordsCheckResult {
  domain: string;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: Array<{ exchange: string; priority: number }>;
  txtRecords: string[];
  nsRecords: string[];
  issues: DNSIssue[];
  provider: string;
}

export interface DNSIssue {
  type: 'MISSING_RECORD' | 'RECORD_COUNT' | 'CONFIGURATION';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  recommendation: string;
  recordType?: string;
}

// ===========================
// 2. DNS-OVER-HTTPS PROVIDERS
// ===========================

const DOH_PROVIDERS = {
  google: {
    url: 'https://dns.google/resolve',
    name: 'Google DNS',
  },
  cloudflare: {
    url: 'https://cloudflare-dns.com/dns-query',
    name: 'Cloudflare DNS',
  },
  // Add more providers as needed
};

/**
 * Perform DNS lookup using DNS-over-HTTPS
 * Uses Google DNS API as primary, Cloudflare as fallback
 */
async function dohLookup(
  domain: string,
  type: 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'DS' | 'DNSKEY',
  provider: 'google' | 'cloudflare' = 'google'
): Promise<{ data: any; provider: string } | null> {
  const config = DOH_PROVIDERS[provider];

  try {
    // Google DNS API format
    const response = await fetch(
      `${config.url}?name=${encodeURIComponent(domain)}&type=${type}`,
      {
        method: 'GET',
        headers: {
          'Accept': 'application/dns-json',
        },
        signal: AbortSignal.timeout(5000), // 5 second timeout
      }
    );

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    return { data, provider: config.name };
  } catch (error) {
    return null;
  }
}

/**
 * Try multiple DoH providers
 */
async function dohLookupWithFallback(
  domain: string,
  type: 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'DS' | 'DNSKEY'
): Promise<{ data: any; provider: string } | null> {
  // Try Google first
  const googleResult = await dohLookup(domain, type, 'google');
  if (googleResult) {
    return googleResult;
  }

  // Try Cloudflare as fallback
  const cloudflareResult = await dohLookup(domain, type, 'cloudflare');
  if (cloudflareResult) {
    return cloudflareResult;
  }

  return null;
}

// ===========================
// 3. DNSSEC VERIFICATION
// ===========================

/**
 * Check if domain has DNSSEC enabled
 * Uses DNS DS (Delegation Signer) records via DoH
 */
export async function checkDNSSEC(domain: string): Promise<DNSSECCheckResult> {
  const result: DNSSECCheckResult = {
    domain,
    hasDNSSEC: false,
    isValid: false,
    provider: 'Unknown',
    errors: [],
    warnings: [],
    severity: 'INFO',
  };

  try {
    // STEP 1: Check for DS records (Delegation Signer)
    // DS records indicate that zone is DNSSEC signed
    const dsLookup = await dohLookupWithFallback(domain, 'DS');

    if (!dsLookup) {
      result.warnings.push('DNS lookup failed - DNSSEC check unavailable');
      result.severity = 'LOW';
      result.recommendation = 'DNSSEC check requires network access. Ensure DNS-over-HTTPS is accessible.';
      return result;
    }

    result.provider = dsLookup.provider;

    // Google DNS API response format
    const googleData = dsLookup.data;

    if (!googleData || !googleData.Answer) {
      result.warnings.push('No DS records found - DNSSEC not enabled');
      result.hasDNSSEC = false;
      result.severity = 'MEDIUM';
      result.recommendation = 'Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks';
      return result;
    }

    // Check if DS record exists
    const dsRecords = googleData.Answer.filter(
      (record: any) => record.type === 53 || record.type === 'DS'
    );

    if (dsRecords.length === 0) {
      result.warnings.push('No DS records found - DNSSEC not enabled');
      result.hasDNSSEC = false;
      result.severity = 'MEDIUM';
      result.recommendation = 'Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks';
      return result;
    }

    result.hasDNSSEC = true;

    // STEP 2: Check DNSKEY records
    // DNSKEY records contain the public keys used to verify DNS records
    const dnskeyLookup = await dohLookupWithFallback(domain, 'DNSKEY');

    if (!dnskeyLookup || !dnskeyLookup.data || !dnskeyLookup.data.Answer) {
      result.errors.push('DNSSEC enabled but DNSKEY records not accessible');
      result.hasDNSSEC = false;
      result.severity = 'HIGH';
      result.recommendation = 'DNSSEC is configured but DNSKEY records are not accessible. Check DNS server configuration.';
      return result;
    }

    const dnskeyRecords = dnskeyLookup.data.Answer.filter(
      (record: any) => record.type === 48 || record.type === 'DNSKEY'
    );

    if (dnskeyRecords.length === 0) {
      result.errors.push('DNSSEC enabled but no DNSKEY records found');
      result.hasDNSSEC = false;
      result.severity = 'HIGH';
      result.recommendation = 'DNSSEC is configured but DNSKEY records are missing. Check DNS server configuration.';
      return result;
    }

    result.isValid = true;
    result.severity = 'INFO' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    result.recommendation = 'DNSSEC is properly configured';

    return result;
  } catch (error: any) {
    result.errors.push(`DNSSEC check error: ${error.message || 'Unknown error'}`);
    result.severity = 'MEDIUM';
    result.recommendation = 'DNSSEC check failed. Network may be unavailable or DNS provider is not responding.';
    return result;
  }
}

// ===========================
// 4. DNS RECORDS CHECK
// ===========================

/**
 * Check basic DNS records configuration using DoH
 */
export async function checkDNSRecords(domain: string): Promise<DNSRecordsCheckResult> {
  const result: DNSRecordsCheckResult = {
    domain,
    aRecords: [],
    aaaaRecords: [],
    mxRecords: [],
    txtRecords: [],
    nsRecords: [],
    issues: [],
    provider: 'Unknown',
  };

  try {
    // Check A records (IPv4)
    const aLookup = await dohLookupWithFallback(domain, 'A');
    if (aLookup && aLookup.data && aLookup.data.Answer) {
      result.aRecords = aLookup.data.Answer
        .filter((r: any) => r.type === 1 || r.type === 'A')
        .map((r: any) => r.data);

      result.provider = aLookup.provider;
    }

    // Check AAAA records (IPv6)
    const aaaaLookup = await dohLookupWithFallback(domain, 'AAAA');
    if (aaaaLookup && aaaaLookup.data && aaaaLookup.data.Answer) {
      result.aaaaRecords = aaaaLookup.data.Answer
        .filter((r: any) => r.type === 28 || r.type === 'AAAA')
        .map((r: any) => r.data);
    }

    // Check MX records (Mail)
    const mxLookup = await dohLookupWithFallback(domain, 'MX');
    if (mxLookup && mxLookup.data && mxLookup.data.Answer) {
      result.mxRecords = mxLookup.data.Answer
        .filter((r: any) => r.type === 15 || r.type === 'MX')
        .map((r: any) => ({
          exchange: r.data,
          priority: r.priority || 0,
        }));
    }

    // Check TXT records
    const txtLookup = await dohLookupWithFallback(domain, 'TXT');
    if (txtLookup && txtLookup.data && txtLookup.data.Answer) {
      result.txtRecords = txtLookup.data.Answer
        .filter((r: any) => r.type === 16 || r.type === 'TXT')
        .map((r: any) => r.data);
    }

    // Check NS records (Nameservers)
    const nsLookup = await dohLookupWithFallback(domain, 'NS');
    if (nsLookup && nsLookup.data && nsLookup.data.Answer) {
      result.nsRecords = nsLookup.data.Answer
        .filter((r: any) => r.type === 2 || r.type === 'NS')
        .map((r: any) => r.data);
    }

    // Analyze DNS configuration
    analyzeDNSConfiguration(result);

    return result;
  } catch (error: any) {
    result.issues.push({
      type: 'CONFIGURATION',
      severity: 'HIGH' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
      title: 'DNS Resolution Failed',
      description: `Could not resolve domain: ${error.message || 'Unknown error'}`,
      recommendation: 'Verify domain exists and is properly configured',
    });

    return result;
  }
}

// ===========================
// 5. DNSSEC + DNS RECORDS COMBINED
// ===========================

export interface FullDNSCheckResult {
  domain: string;
  dnssec: DNSSECCheckResult;
  dnsRecords: DNSRecordsCheckResult;
  overallSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  offlineMode: boolean;
}

/**
 * Perform comprehensive DNS check (DNSSEC + Records)
 * Falls back to offline mode if DoH is unavailable
 */
export async function performFullDNSCheck(domain: string): Promise<FullDNSCheckResult> {
  try {
    const [dnssecResult, dnsRecordsResult] = await Promise.all([
      checkDNSSEC(domain),
      checkDNSRecords(domain),
    ]);

    // Calculate overall severity
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    let overallSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' = 'INFO';

    // Get highest severity from both results
    const allIssues = [
      ...dnssecResult.errors.map(err => ({
        title: 'DNSSEC Error',
        description: err,
        severity: dnssecResult.severity,
      })),
      ...dnssecResult.warnings.map(warn => ({
        title: 'DNSSEC Warning',
        description: warn,
        severity: dnssecResult.severity === 'INFO' ? 'LOW' : dnssecResult.severity,
      })),
      ...dnsRecordsResult.issues.map(issue => issue),
    ];

    if (allIssues.length > 0) {
      allIssues.forEach(issue => {
        const currentIndex = severities.indexOf(issue.severity);
        const currentHigh = severities.indexOf(overallSeverity);
        if (currentIndex < currentHigh) {
          overallSeverity = issue.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
        }
      });
    }

    // Generate summary
    let summary = `DNSSEC: ${dnssecResult.hasDNSSEC ? 'Enabled' : 'Disabled'} (${dnssecResult.provider})`;
    if (dnsRecordsResult.nsRecords.length > 0) {
      summary += `, ${dnsRecordsResult.nsRecords.length} Nameservers`;
    }
    if (dnsRecordsResult.aRecords.length > 0) {
      summary += `, ${dnsRecordsResult.aRecords.length} A Records`;
    }

    return {
      domain,
      dnssec: dnssecResult,
      dnsRecords: dnsRecordsResult,
      overallSeverity,
      summary,
      offlineMode: false,
    };
  } catch (error: any) {
    // Offline mode - DNS over HTTPS not available
    return {
      domain,
      dnssec: {
        domain,
        hasDNSSEC: false,
        isValid: false,
        provider: 'Offline',
        errors: ['DNS-over-HTTPS not available'],
        warnings: [],
        severity: 'INFO' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
        recommendation: 'Network access required for DNS checks. Tool works in closed networks with limited DNS functionality.',
      },
      dnsRecords: {
        domain,
        aRecords: [],
        aaaaRecords: [],
        mxRecords: [],
        txtRecords: [],
        nsRecords: [],
        issues: [],
        provider: 'Offline',
      },
      overallSeverity: 'INFO' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
      summary: 'Offline mode - DNS checks not available',
      offlineMode: true,
    };
  }
}

// ===========================
// 6. HELPER FUNCTIONS
// ===========================

/**
 * Analyze DNS configuration for common issues
 */
function analyzeDNSConfiguration(result: DNSRecordsCheckResult) {
  // Issue: No A records found
  if (result.aRecords.length === 0) {
    result.issues.push({
      type: 'MISSING_RECORD',
      severity: 'CRITICAL' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
      title: 'No A Records',
      description: 'Domain has no A (IPv4) records',
      recommendation: 'Add A records pointing to your server IP address',
      recordType: 'A',
    });
  }

  // Issue: Single nameserver (no redundancy)
  if (result.nsRecords.length === 1) {
    result.issues.push({
      type: 'RECORD_COUNT',
      severity: 'MEDIUM' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
      title: 'Single Nameserver',
      description: 'Only one nameserver configured. Redundancy is important for reliability.',
      recommendation: 'Add at least one more nameserver from a different network for redundancy',
      recordType: 'NS',
    });
  }

  // Issue: No MX records (if it looks like an email domain)
  if (result.mxRecords.length === 0) {
    result.issues.push({
      type: 'MISSING_RECORD',
      severity: 'INFO' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
      title: 'No MX Records',
      description: 'No MX records found. Email delivery may be affected.',
      recommendation: 'If you need email delivery, configure MX records pointing to your mail server',
      recordType: 'MX',
    });
  }

  // Only check email security records (SPF, DMARC) if MX records exist
  // These are only relevant for email-enabled domains
  if (result.mxRecords.length > 0) {
    // Check for SPF record
    const hasSPF = result.txtRecords.some(txt =>
      typeof txt === 'string' && txt.toLowerCase().startsWith('v=spf1')
    );

    if (!hasSPF) {
      result.issues.push({
        type: 'MISSING_RECORD',
        severity: 'MEDIUM' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
        title: 'Missing SPF Record',
        description: 'No SPF (Sender Policy Framework) record found in DNS.',
        recommendation: 'Add SPF record to prevent email spoofing. Example: "v=spf1 include:_spf.google.com ~all"',
        recordType: 'TXT',
      });
    }

    // Check for DMARC record
    const hasDMARC = result.txtRecords.some(txt =>
      typeof txt === 'string' && (
        txt.toLowerCase().includes('v=dmarc1') ||
        txt.toLowerCase().includes('v=dmarc')
      )
    );

    if (!hasDMARC) {
      result.issues.push({
        type: 'MISSING_RECORD',
        severity: 'MEDIUM' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
        title: 'Missing DMARC Record',
        description: 'No DMARC (Domain-based Message Authentication, Reporting, and Conformance) record found.',
        recommendation: 'Add DMARC record for email authentication. Example: "v=DMARC1; p=none; rua=mailto:dmarc@example.com"',
        recordType: 'TXT',
      });
    }
  }
}

/**
 * Generate DNS security score (0-100)
 */
export function generateDNSSecurityScore(result: FullDNSCheckResult): number {
  // In offline mode, return neutral score
  if (result.offlineMode) {
    return 50;
  }

  let score = 100;

  // DNSSEC enabled
  if (!result.dnssec.hasDNSSEC) {
    score -= 20;
  }

  // DNSSEC valid
  if (result.dnssec.hasDNSSEC && !result.dnssec.isValid) {
    score -= 15;
  }

  // Nameserver redundancy
  if (result.dnsRecords.nsRecords.length === 1) {
    score -= 10;
  }

  // SPF and DMARC only matter if MX records exist (email domain)
  if (result.dnsRecords.mxRecords.length > 0) {
    // SPF missing
    const hasSPF = result.dnsRecords.issues.some(
      (issue: DNSIssue) => issue.title === 'Missing SPF Record'
    );
    if (hasSPF) {
      score -= 10;
    }

    // DMARC missing
    const hasDMARC = result.dnsRecords.issues.some(
      (issue: DNSIssue) => issue.title === 'Missing DMARC Record'
    );
    if (hasDMARC) {
      score -= 10;
    }
  }

  // DNS errors
  score -= result.dnssec.errors.length * 15;
  score -= result.dnsRecords.issues.filter(
    (issue: DNSIssue) => issue.severity === 'CRITICAL' || issue.severity === 'HIGH'
  ).length * 20;

  return Math.max(0, score);
}

/**
 * Check if DNS is available (network connectivity test)
 */
export async function isDNSAvailable(): Promise<boolean> {
  try {
    const response = await fetch('https://dns.google/resolve?name=example.com&type=A', {
      method: 'GET',
      signal: AbortSignal.timeout(3000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

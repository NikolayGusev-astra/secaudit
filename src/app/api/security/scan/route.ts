import { NextRequest, NextResponse } from 'next/server'
import { checkVulnerability } from '@/lib/vulnerability-db.js'
import { 
  analyzeCSPPolicy, 
  analyzeCookieSecurity, 
  SPA_PATTERNS_DB, 
  OWASP_PATTERNS_DB 
} from '@/lib/security-patterns-db'
import { 
  checkLibraryVulnerabilityHybrid, 
  generateVulnerabilitySummary, 
  hasInternetAccess 
} from '@/lib/hybrid-vulnerability-checker'
import { 
  performFullDNSCheck, 
  generateDNSSecurityScore, 
  isDNSAvailable 
} from '@/lib/dnssec-checker'

// Helper function to parse URL and extract domain
function parseUrl(url: string) {
  try {
    const parsed = new URL(url)
    return {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port,
      pathname: parsed.pathname,
      domain: parsed.hostname,
    }
  } catch {
    return null
  }
}

// SSL/TLS Certificate Checker
async function checkSSL(hostname: string) {
  try {
    const start = Date.now()
    const response = await fetch(`https://${hostname}`, {
      method: 'HEAD',
      redirect: 'manual',
    })
    const responseTime = Date.now() - start

    const sslCheck = {
      hasCertificate: response.url.startsWith('https://'),
      isValid: response.ok || response.status === 301 || response.status === 302,
      issuer: undefined as string | undefined,
      validFrom: undefined as Date | undefined,
      validTo: undefined as Date | undefined,
      daysUntilExpiry: undefined as number | undefined,
      tlsVersion: 'TLS 1.3' as string | undefined,
      hasWeakCiphers: false,
      isSelfSigned: false,
      isExpired: false,
      isTrusted: true,
      issues: [] as string[],
      score: 0,
    }

    // Calculate score
    let score = 50
    if (sslCheck.hasCertificate) score += 30
    if (sslCheck.isValid) score += 15
    if (sslCheck.tlsVersion) score += 5

    sslCheck.score = Math.min(score, 100)

    return sslCheck
  } catch (error) {
    console.error('SSL check error:', error)
    return {
      hasCertificate: false,
      isValid: false,
      issuer: undefined,
      validFrom: undefined,
      validTo: undefined,
      daysUntilExpiry: undefined,
      tlsVersion: undefined,
      hasWeakCiphers: false,
      isSelfSigned: false,
      isExpired: false,
      isTrusted: false,
      issues: ['Failed to establish SSL connection'],
      score: 0,
    }
  }
}

// Security Headers Checker with Enhanced CSP Analysis
async function checkSecurityHeaders(url: string) {
  try {
    const response = await fetch(url, { method: 'HEAD' })
    const headers = Object.fromEntries(response.headers.entries())

    const importantHeaders = [
      'content-security-policy',
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
      'x-xss-protection',
      'referrer-policy',
      'permissions-policy',
    ]

    const missingHeaders: string[] = []
    const issues: any[] = []

    importantHeaders.forEach(header => {
      if (!headers[header]) {
        missingHeaders.push(header)
      }
    })

    // Analyze HSTS
    const hsts = headers['strict-transport-security']
    let hasHSTSIncludeSubdomains = false
    let hasHSTSPreload = false
    let hstsMaxAge = 0

    if (hsts) {
      const match = hsts.match(/max-age=(\d+)/)
      if (match) {
        hstsMaxAge = parseInt(match[1])
      }
      hasHSTSIncludeSubdomains = hsts.includes('includeSubDomains')
      hasHSTSPreload = hsts.includes('preload')
    }

    // Enhanced CSP Analysis using security-patterns-db
    const cspValue = headers['content-security-policy']
    if (cspValue) {
      const cspIssues = analyzeCSPPolicy(cspValue)
      issues.push(...cspIssues)
    } else {
      // Missing CSP - add OWASP pattern
      const missingCSP = OWASP_PATTERNS_DB['missing-csp'] as any
      if (missingCSP) {
        issues.push({
          ...missingCSP,
          evidence: { url },
        })
      }
    }

    // Check for information disclosure
    const server = headers['server']
    const xPoweredBy = headers['x-powered-by']

    if (server && server !== 'cloudflare') {
      const serverHeaderDisclosure = OWASP_PATTERNS_DB['server-header-disclosure'] as any
      if (serverHeaderDisclosure) {
        issues.push({
          ...serverHeaderDisclosure,
          evidence: { server },
        })
      }
    }

    if (xPoweredBy) {
      issues.push({
        title: 'X-Powered-By Header Disclosure',
        severity: 'INFO',
        description: `X-Powered-By header discloses: ${xPoweredBy}`,
        recommendation: 'Remove X-Powered-By header in production.',
        category: 'INFORMATION_DISCLOSURE',
      })
    }

    // Calculate score
    const presentCount = importantHeaders.length - missingHeaders.length
    const score = Math.round((presentCount / importantHeaders.length) * 100)

    return {
      hasCSP: !!headers['content-security-policy'],
      cspValue: headers['content-security-policy'],
      hasHSTS: !!hsts,
      hstsValue: hsts,
      hstsMaxAge,
      hasHSTSIncludeSubdomains,
      hasHSTSPreload,
      hasXFrameOptions: !!headers['x-frame-options'],
      xFrameOptions: headers['x-frame-options'],
      hasXContentTypeOptions: !!headers['x-content-type-options'],
      hasXSSProtection: !!headers['x-xss-protection'],
      xssProtection: headers['x-xss-protection'],
      hasReferrerPolicy: !!headers['referrer-policy'],
      referrerPolicy: headers['referrer-policy'],
      hasPermissionsPolicy: !!headers['permissions-policy'],
      permissionsPolicy: headers['permissions-policy'],
      hasStrictTransportSecurity: !!hsts,
      hasServerHeader: !!server,
      serverValue: server,
      hasXPoweredBy: !!xPoweredBy,
      missingHeaders,
      issues,
      score,
    }
  } catch (error) {
    console.error('Security headers check error:', error)
    return {
      hasCSP: false,
      cspValue: undefined,
      hasHSTS: false,
      hstsValue: undefined,
      hstsMaxAge: undefined,
      hasHSTSIncludeSubdomains: false,
      hasHSTSPreload: false,
      hasXFrameOptions: false,
      xFrameOptions: undefined,
      hasXContentTypeOptions: false,
      hasXSSProtection: false,
      xssProtection: undefined,
      hasReferrerPolicy: false,
      referrerPolicy: undefined,
      hasPermissionsPolicy: false,
      permissionsPolicy: undefined,
      hasStrictTransportSecurity: false,
      hasServerHeader: false,
      serverValue: undefined,
      hasXPoweredBy: false,
      missingHeaders: ['Failed to check security headers'],
      issues: ['Failed to check security headers'],
      score: 0,
    }
  }
}

// DNS Checker using enhanced dnssec-checker
async function checkDNS(domain: string) {
  try {
    // Use enhanced DNS check with DNSSEC
    const dnsCheck = await performFullDNSCheck(domain)
    const dnsIssues = dnsCheck.dnsRecords.issues || []

    const hasSPF = dnsCheck.dnsRecords.txtRecords.some(txt =>
      typeof txt === 'string' && txt.toLowerCase().startsWith('v=spf1')
    )

    const hasDMARC = dnsCheck.dnsRecords.txtRecords.some(txt =>
      typeof txt === 'string' && (
        txt.toLowerCase().includes('v=dmarc1') ||
        txt.toLowerCase().includes('v=dmarc')
      )
    )

    const hasDKIM = dnsCheck.dnsRecords.txtRecords.some(txt =>
      typeof txt === 'string' && txt.toLowerCase().includes('v=dkim1')
    )
    
    // Detect if website has email functionality (contact forms, newsletter, signup, etc.)
    // This affects scoring: email features require SPF/DMARC/DKIM protection
    const hasEmailFunctionality = detectEmailFunctionality(url, domain)
    
    // Calculate score
    let score = 0
    if (dnsCheck.dnsRecords.aRecords.length > 0) score += 20
    if (dnsCheck.dnsRecords.nsRecords.length > 0) score += 10

    // Only check email security if MX records exist
    if (dnsCheck.dnsRecords.mxRecords.length > 0) {
      if (hasSPF) score += 20
      if (hasDMARC) score += 20
      if (hasDKIM) score += 15
    } else {
      if (dnsCheck.offlineMode) {
        const offlineIssue = {
          type: 'CONFIGURATION' as 'MISSING_RECORD' | 'RECORD_COUNT' | 'CONFIGURATION',
          severity: 'INFO' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
          title: 'Offline Mode',
          description: 'DNS checks are unavailable in offline mode',
          recommendation: 'Network access required for DNS checks',
        }
        dnsIssues.push(offlineIssue as any)
      }
      // Add bonus score if MX records don't exist (email not used)
      // Email security is N/A, not a vulnerability
      score += 10
    }

    if (dnsCheck.dnsRecords.mxRecords.length > 0) score += 15

    return {
      ...dnsCheck,
      hasARecord: dnsCheck.dnsRecords.aRecords.length > 0,
      hasAAAARecord: dnsCheck.dnsRecords.aaaaRecords.length > 0,
      hasMXRecord: dnsCheck.dnsRecords.mxRecords.length > 0,
      hasTXTRecord: dnsCheck.dnsRecords.txtRecords.length > 0,
      hasNSRecord: dnsCheck.dnsRecords.nsRecords.length > 0,
      hasSPF,
      spfValid: hasSPF,
      hasDMARC,
      dmarcPolicy: hasDMARC ? 'enabled' : 'disabled',
      dmarcValid: hasDMARC,
      hasDKIM,
      hasDNSSEC: dnsCheck.dnssec && dnsCheck.dnssec.hasDNSSEC,
      dnsRecords: dnsCheck.dnsRecords.aRecords.length + dnsCheck.dnsRecords.aaaaRecords.length,
      issues: dnsIssues,
      score,
      offlineMode: dnsCheck.offlineMode,
    }
  } catch (error) {
    console.error('DNS check error:', error)
    return {
      hasARecord: false,
      hasAAAARecord: false,
      hasMXRecord: false,
      hasTXTRecord: false,
      hasNSRecord: false,
      hasSPF: false,
      spfRecord: undefined,
      spfValid: false,
      hasDMARC: false,
      dmarcRecord: undefined,
      dmarcPolicy: undefined,
      dmarcValid: false,
      hasDKIM: false,
      hasDNSSEC: score,
      dnsRecords: [],
      issues: [{ type: 'CONFIGURATION', severity: 'HIGH', title: 'Failed to perform DNS lookup', description: 'Network error', recommendation: 'Check network connectivity' }],
      score: 0,
      offlineMode: true,
    }
  }
}
// DNS Checker using enhanced dnssec-checker
async function checkDNS(domain: string) {
  try {
    // Use enhanced DNS check with DNSSEC
    const dnsCheck = await performFullDNSCheck(domain)
    const dnsIssues = dnsCheck.dnsRecords.issues || []

    const hasSPF = dnsCheck.dnsRecords.txtRecords.some(txt =>
      typeof txt === 'string' && txt.toLowerCase().startsWith('v=spf1')
    )

    const hasDMARC = dnsCheck.dnsRecords.txtRecords.some(txt =>
      typeof txt === 'string' && (
        txt.toLowerCase().includes('v=dmarc1') ||
        txt.toLowerCase().includes('v=dmarc')
      )
    )

    const hasDKIM = dnsCheck.dnsRecords.txtRecords.some(txt =>
      typeof txt === 'string' && txt.toLowerCase().includes('v=dkim1')
    )
    
    // Detect if website has email functionality (contact forms, newsletter, signup, etc.)
    // This affects scoring: email features require SPF/DMARC/DKIM protection
    const hasEmailFunctionality = detectEmailFunctionality(url, domain)
    
    // Calculate score
    let score = 0
    if (dnsCheck.dnsRecords.aRecords.length > 0) score += 20
    if (dnsCheck.dnsRecords.nsRecords.length > 0) score += 10

    // Only check email security if MX records exist
    if (dnsCheck.dnsRecords.mxRecords.length > 0) {
      if (hasSPF) score += 20
      if (hasDMARC) score += 20
      if (hasDKIM) score += 15
    } else {
      if (dnsCheck.offlineMode) {
        const offlineIssue = {
          type: 'CONFIGURATION' as 'MISSING_RECORD' | 'RECORD_COUNT' | 'CONFIGURATION',
          severity: 'INFO' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
          title: 'Offline Mode',
          description: 'DNS checks are unavailable in offline mode',
          recommendation: 'Network access required for DNS checks',
        }
        dnsIssues.push(offlineIssue as any)
      }
      // Add bonus score if MX records don't exist (email not used)
      // Email security is N/A, not a vulnerability
      score += 10
    }

    if (dnsCheck.dnsRecords.mxRecords.length > 0) score += 15

    return {
      ...dnsCheck,
      hasARecord: dnsCheck.dnsRecords.aRecords.length > 0,
      hasAAAARecord: dnsCheck.dnsRecords.aaaaRecords.length > 0,
      hasMXRecord: dnsCheck.dnsRecords.mxRecords.length > 0,
      hasTXTRecord: dnsCheck.dnsRecords.txtRecords.length > 0,
      hasNSRecord: dnsCheck.dnsRecords.nsRecords.length > 0,
      hasSPF,
      spfValid: hasSPF,
      hasDMARC,
      dmarcPolicy: hasDMARC ? 'enabled' : 'disabled',
      dmarcValid: hasDMARC,
      hasDKIM,
      hasDNSSEC: dnsCheck.dnssec && dnsCheck.dnssec.hasDNSSEC,
      dnsRecords: dnsCheck.dnsRecords.aRecords.length + dnsCheck.dnsRecords.aaaaRecords.length,
      issues: dnsIssues,
      score,
      offlineMode: dnsCheck.offlineMode,
    }
  } catch (error) {
    console.error('DNS check error:', error)
    return {
      hasARecord: false,
      hasAAAARecord: false,
      hasMXRecord: false,
      hasTXTRecord: false,
      hasNSRecord: false,
      hasSPF: false,
      spfRecord: undefined,
      spfValid: false,
      hasDMARC: false,
      dmarcRecord: undefined,
      dmarcPolicy: undefined,
      dmarcValid: false,
      hasDKIM: false,
      hasDNSSEC: false,
      dnsRecords: [],
      issues: [{ type: 'CONFIGURATION', severity: 'HIGH', title: 'Failed to perform DNS lookup', description: 'Network error', recommendation: 'Check network connectivity' }],
      score: 0,
      offlineMode: true,
    }
  }
}

// Helper function to detect email functionality on website
function detectEmailFunctionality(url: string, domain: string): boolean {
  // Patterns for email-related functionality
  const emailPatterns = [
    /<form[^>]*action=["'][^"']+["'][^>]*>/gi,  // Contact forms
    /<input[^>]*type=["'][^"']+["'][^>]*email["']/gi,  // Email inputs
    /<input[^>]*name=["'][^"']+["'][^>]*newsletter["']/gi,  // Newsletter signup
    /<a[^>]+href=["']mailto:[^"']+["'][^>]*>/gi,  // Mailto links
    /<button[^>]+href=["'][^"']+["'][^>]*subscribe["']/gi,  // Subscribe buttons
    /(?:signup|register|newsletter|contact)[\s-]+(?:form|button|a)/gi,  // Email-related URLs
  ]
  
  return emailPatterns.some(pattern => {
    const domainPattern = new RegExp(domain.replace(/\./g, '\\.'), 'gi')
    return pattern.test(url) || domainPattern.test(url)
  })
}

    // Calculate score
    let score = 0
    if (dnsCheck.dnsRecords.aRecords.length > 0) score += 20
    if (dnsCheck.dnsRecords.nsRecords.length > 0) score += 10

    // Only check email security if MX records exist
    if (dnsCheck.dnsRecords.mxRecords.length > 0) {
      if (hasSPF) score += 20
      if (hasDMARC) score += 20
      if (hasDKIM) score += 15
    } else {
      if (dnsCheck.offlineMode) {
        const offlineIssue = {
          type: 'CONFIGURATION' as 'MISSING_RECORD' | 'RECORD_COUNT' | 'CONFIGURATION',
          severity: 'INFO' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
          title: 'Offline Mode',
          description: 'DNS checks are unavailable in offline mode',
          recommendation: 'Network access required for DNS checks',
        }
        dnsIssues.push(offlineIssue as any)
      }
      // Add bonus score if MX records don't exist (email not used)
      // Email security is N/A, not a vulnerability
      score += 10
    }

    if (dnsCheck.dnsRecords.mxRecords.length > 0) score += 15

    return {
      ...dnsCheck,
      hasARecord: dnsCheck.dnsRecords.aRecords.length > 0,
      hasAAAARecord: dnsCheck.dnsRecords.aaaaRecords.length > 0,
      hasMXRecord: dnsCheck.dnsRecords.mxRecords.length > 0,
      hasTXTRecord: dnsCheck.dnsRecords.txtRecords.length > 0,
      hasNSRecord: dnsCheck.dnsRecords.nsRecords.length > 0,
      hasSPF,
      spfValid: hasSPF,
      hasDMARC,
      dmarcPolicy: hasDMARC ? 'enabled' : 'disabled',
      dmarcValid: hasDMARC,
      hasDKIM,
      hasDNSSEC: dnsCheck.dnssec && dnsCheck.dnssec.hasDNSSEC,
      dnsRecords: dnsCheck.dnsRecords.aRecords.length + dnsCheck.dnsRecords.aaaaRecords.length,
      issues: dnsIssues,
      score,
      offlineMode: dnsCheck.offlineMode,
    }
  } catch (error) {
    console.error('DNS check error:', error)
    return {
      hasARecord: false,
      hasAAAARecord: false,
      hasMXRecord: false,
      hasTXTRecord: false,
      hasNSRecord: false,
      hasSPF: false,
      spfRecord: undefined,
      spfValid: false,
      hasDMARC: false,
      dmarcRecord: undefined,
      dmarcPolicy: undefined,
      dmarcValid: false,
      hasDKIM: false,
      hasDNSSEC: false,
      dnsRecords: [],
      issues: [{ type: 'CONFIGURATION', severity: 'HIGH', title: 'Failed to perform DNS lookup', description: 'Network error', recommendation: 'Check network connectivity' }],
      score: 0,
      offlineMode: true,
    }
  }
}

// Performance Checker
async function checkPerformance(url: string) {
  try {
    const start = Date.now()
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
    })

    const responseTime = Date.now() - start
    const headers = Object.fromEntries(response.headers.entries())

    // Extract timing information if available
    const ttfb = parseInt(headers['x-response-time'] || '0') || responseTime / 2

    const hasGzip = headers['content-encoding']?.includes('gzip') || false
    const hasBrotli = headers['content-encoding']?.includes('br') || false

    // Detect HTTP version
    const httpVersion = headers[':status'] ? 'HTTP/3' : 'HTTP/2'

    // Calculate score
    let score = 60 // Base score
    if (responseTime < 500) score += 20
    else if (responseTime < 1000) score += 10
    else if (responseTime < 2000) score += 5

    // Award points for any compression (GZIP or Brotli)
    if (hasGzip || hasBrotli) score += 10
    // Extra point for having both
    if (hasGzip && hasBrotli) score += 5

    score = Math.min(score, 100)

    return {
      statusCode: response.status,
      responseTime,
      ttfb,
      domContentLoaded: undefined,
      loadComplete: undefined,
      totalSize: parseInt(headers['content-length'] || '0'),
      htmlSize: undefined,
      cssSize: undefined,
      jsSize: undefined,
      imageSize: undefined,
      totalResources: undefined,
      scriptCount: undefined,
      stylesheetCount: undefined,
      imageCount: undefined,
      hasGzip,
      hasBrotli,
      compressionSavings: undefined,
      hasCacheControl: !!headers['cache-control'],
      hasETag: !!headers['etag'],
      hasLastModified: !!headers['last-modified'],
      httpVersion,
      recommendations: [],
      score,
    }
  } catch (error) {
    console.error('Performance check error:', error)
    return {
      statusCode: 0,
      responseTime: 0,
      ttfb: undefined,
      domContentLoaded: undefined,
      loadComplete: undefined,
      totalSize: undefined,
      htmlSize: undefined,
      cssSize: undefined,
      jsSize: undefined,
      imageSize: undefined,
      totalResources: undefined,
      scriptCount: undefined,
      stylesheetCount: undefined,
      imageCount: undefined,
      hasGzip: false,
      hasBrotli: false,
      compressionSavings: undefined,
      hasCacheControl: false,
      hasETag: false,
      hasLastModified: false,
      httpVersion: undefined,
      recommendations: ['Failed to check performance'],
      score: 0,
    }
  }
}

// Cookie Security Analyzer using security-patterns-db
function analyzeCookies(headers: Record<string, string>, html: string) {
  const issues: any[] = []
  const setCookie = headers['set-cookie']
  const cookies = typeof setCookie === 'string' ? [setCookie] : (setCookie || [])

  if (cookies.length > 0) {
    // Use enhanced cookie security analysis
    const cookieIssues = analyzeCookieSecurity(cookies)
    issues.push(...cookieIssues)
  }

  return issues
}

// CORS Policy Analyzer
function analyzeCORS(headers: Record<string, string>) {
  const issues: any[] = []
  const corsHeaders = {
    'access-control-allow-origin': headers['access-control-allow-origin'],
    'access-control-allow-credentials': headers['access-control-allow-credentials'],
    'access-control-allow-methods': headers['access-control-allow-methods'],
    'access-control-allow-headers': headers['access-control-allow-headers'],
    'access-control-max-age': headers['access-control-max-age'],
    'access-control-expose-headers': headers['access-control-expose-headers'],
  }

  // Check for wildcard origin with credentials
  if (corsHeaders['access-control-allow-origin'] === '*' &&
      corsHeaders['access-control-allow-credentials'] === 'true') {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'HIGH',
      title: 'CORS Misconfiguration: Wildcard Origin with Credentials',
      description: 'Using wildcard origin (*) with credentials is a security risk and will be blocked by browsers.',
      recommendation: 'Replace wildcard origin with specific allowed origins when using credentials.',
      evidence: {
        origin: '*',
        credentials: 'true'
      },
    })
  }

  // Check for overly permissive CORS
  if (corsHeaders['access-control-allow-origin'] === '*') {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'MEDIUM',
      title: 'Overly Permissive CORS Policy',
      description: 'CORS allows requests from any origin (*), which may be too permissive.',
      recommendation: 'Restrict CORS to specific, trusted origins only.',
      evidence: { origin: '*' },
    })
  }

  // Check for missing CORS headers (if API endpoint)
  if (!corsHeaders['access-control-allow-origin']) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'INFO',
      title: 'No CORS Headers Detected',
      description: 'No CORS headers found. May be intentional if no cross-origin access is needed.',
      recommendation: 'Configure CORS headers if API is accessed from different origins.',
    })
  }

  return issues
}

// SRI (Subresource Integrity) Checker using security-patterns-db
function checkSRI(html: string, url: string) {
  const issues: any[] = []

  // Find script and link tags
  const scriptPattern = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi
  const linkPattern = /<link[^>]+href=["']([^"']+)["'][^>]*>/gi

  const scripts = html.match(scriptPattern) || []
  const links = html.match(linkPattern) || []

  // Check external resources for SRI
  const checkResourceForSRI = (tag: string, src: string) => {
    if (src.startsWith('http')) {
      const hasIntegrity = /integrity=["']([^"']+)["']/i.test(tag)

      if (!hasIntegrity) {
        const missingSRI = OWASP_PATTERNS_DB['missing-sri'] as any
        if (missingSRI) {
          issues.push({
            ...missingSRI,
            evidence: { url: src },
          })
        }
      }
    }
  }

  scripts.forEach((script) => {
    const srcMatch = script.match(/src=["']([^"']+)["']/i)
    if (srcMatch) {
      checkResourceForSRI(script, srcMatch[1])
    }
  })

  links.forEach((link) => {
    const hrefMatch = link.match(/href=["']([^"']+)["']/i)
    if (hrefMatch) {
      checkResourceForSRI(link, hrefMatch[1])
    }
  })

  return issues
}

// WAF Detection
function detectWAF(headers: Record<string, string>) {
  const wafSignatures = {
    'cloudflare': 'Cloudflare WAF',
    'akamai': 'Akamai WAF',
    'fastly': 'Fastly WAF',
    'incapsula': 'Imperva Incapsula',
    'sucuri': 'Sucuri WAF',
    'azure': 'Azure WAF',
    'aws': 'AWS WAF',
    'modsecurity': 'ModSecurity',
    'barracuda': 'Barracuda WAF',
  }

  const detected: Array<{ signature: string; name: string }> = []
  const headerString = JSON.stringify(headers).toLowerCase()

  Object.entries(wafSignatures).forEach(([signature, name]) => {
    if (headerString.includes(signature)) {
      detected.push({ signature, name })
    }
  })

  return detected
}

// Content Injection Checks using security-patterns-db
function checkContentInjection(html: string, url: string) {
  const issues: any[] = []

  // Check for reflected parameters in HTML
  const patterns = [
    /<script>[^<]*(?:<%=|\$\{|\{\{|\{#)/i,
    /onclick=["'][^"']*(?:<%=|\$\{|\{\{|\{#)/i,
    /eval\(\s*(?:<%=|\$\{|\{\{|\{#)/i,
  ]

  patterns.forEach((pattern) => {
    if (pattern.test(html)) {
      const evalPattern = OWASP_PATTERNS_DB['eval-pattern'] as any
      if (evalPattern) {
        issues.push({
          ...evalPattern,
          evidence: { pattern: pattern.source },
        })
      }
    }
  })

  // Check for javascript: protocol
  const jsProtocolPattern = /javascript:/gi
  if (jsProtocolPattern.test(html)) {
    const jsHrefPattern = OWASP_PATTERNS_DB['javascript-href'] as any
    if (jsHrefPattern) {
      issues.push({
        ...jsHrefPattern,
        evidence: { count: (html.match(jsProtocolPattern) || []).length },
      })
    }
  }

  // Check for inline event handlers
  const eventHandlerPattern = /on\w+\s*=\s*["'][^"']*["']/gi
  if (eventHandlerPattern.test(html)) {
    const inlineHandlerPattern = OWASP_PATTERNS_DB['inline-event-handlers'] as any
    if (inlineHandlerPattern) {
      issues.push({
        ...inlineHandlerPattern,
        evidence: { count: (html.match(eventHandlerPattern) || []).length },
      })
    }
  }

  // Check for dangerouslySetInnerHTML (React pattern)
  const dangerousInnerHTMLPattern = /dangerouslySetInnerHTML/gi
  if (dangerousInnerHTMLPattern.test(html)) {
    const pattern = SPA_PATTERNS_DB['dangerously-set-innerhtml'] as any
    if (pattern) {
      issues.push({
        ...pattern,
        evidence: { count: (html.match(dangerousInnerHTMLPattern) || []).length },
      })
    }
  }

  return issues
}

// Open Graph and Social Media Analysis
function analyzeSocialMetadata(html: string) {
  const issues: any[] = []
  const metadata = {
    ogTitle: /<meta[^>]+property=["']og:title["'][^>]*>/gi.test(html),
    ogDescription: /<meta[^>]+property=["']og:description["'][^>]*>/gi.test(html),
    ogImage: /<meta[^>]+property=["']og:image["'][^>]*>/gi.test(html),
    ogUrl: /<meta[^>]+property=["']og:url["'][^>]*>/gi.test(html),
    ogType: /<meta[^>]+property=["']og:type["'][^>]*>/gi.test(html),
    twitterCard: /<meta[^>]+name=["']twitter:card["'][^>]*>/gi.test(html),
  }

  // Check for missing basic Open Graph tags
  if (!metadata.ogTitle) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'LOW',
      title: 'Missing Open Graph Title',
      description: 'Missing og:title meta tag may result in poor social media sharing experience.',
      recommendation: 'Add Open Graph title tag: <meta property="og:title" content="Your Title">',
    })
  }

  if (!metadata.ogDescription) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'LOW',
      title: 'Missing Open Graph Description',
      description: 'Missing og:description meta tag may result in poor social media sharing experience.',
      recommendation: 'Add Open Graph description tag: <meta property="og:description" content="Your Description">',
    })
  }

  if (!metadata.ogImage) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'LOW',
      title: 'Missing Open Graph Image',
      description: 'Missing og:image meta tag may result in poor social media sharing experience.',
      recommendation: 'Add Open Graph image tag: <meta property="og:image" content="https://example.com/image.jpg">',
    })
  }

  return issues
}

// Enhanced Library Vulnerability Checker using Hybrid approach
async function checkLibraryCVEsHybrid(libraryName: string, version: string) {
  try {
    // Use hybrid vulnerability checker
    const result = await checkLibraryVulnerabilityHybrid(libraryName, version)

    if (result.isVulnerable) {
      return {
        hasVulnerabilities: true,
        criticalCount: result.severity === 'CRITICAL' ? 1 : 0,
        highCount: result.severity === 'HIGH' ? 1 : 0,
        totalCount: 1,
        severity: result.severity,
        details: [{
          id: result.cve || 'UNKNOWN',
          summary: result.description || '',
          severity: result.severity,
          source: result.source,
          externalAPIAvailable: result.externalAPIAvailable,
        }]
      }
    }

    return { hasVulnerabilities: false, source: result.source }
  } catch (error) {
    console.error('CVE check error:', error)
    return { hasVulnerabilities: false, error: true }
  }
}

// Common Sensitive Files Discovery with Smart Content Validation
async function checkSensitiveFiles(baseUrl: string, domain: string) {
  const issues: any[] = []

  const sensitiveFiles = [
    '/.git/config',
    '/.env',
    '/.env.local',
    '/.env.production',
    '/debug.log',
    '/error.log',
    '/access.log',
    '/readme.md',
    '/README.md',
    '/changelog.md',
    '/CHANGELOG.md',
    '/wp-admin',
    '/admin',
    '/administrator',
    '/phpmyadmin',
    '/phpMyAdmin',
    '/.well-known/security.txt',
    '/security.txt',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
    '/.DS_Store',
    '/Thumbs.db'
  ]

  // Smart ignore patterns based on detected stack
  const IGNORE_PATTERNS: Record<string, string[]> = {
    'vercel': ['/wp-admin', '/phpmyadmin', '/administrator', '/.git', '/admin'],
    'nextjs': ['/wp-admin', '/phpmyadmin', '/administrator'],
    'netlify': ['/wp-admin', '/phpmyadmin', '/administrator'],
    'github': ['/wp-admin', '/phpmyadmin', '/administrator'],
    'cloudflare': ['/wp-admin', '/phpmyadmin', '/administrator']
  }

  // Detect stack from domain
  let detectedStack = 'unknown'
  if (domain.includes('vercel.app')) detectedStack = 'vercel'
  else if (domain.includes('netlify.app')) detectedStack = 'netlify'
  else if (domain.includes('github.io')) detectedStack = 'github'

  for (const file of sensitiveFiles) {
    // Skip files based on stack detection
    const ignores = IGNORE_PATTERNS[detectedStack]
    if (ignores && ignores.some(ignore => file.includes(ignore))) {
      continue
    }

    try {
      const response = await fetch(baseUrl + file, {
        method: 'HEAD',
        redirect: 'manual',
      })

      // Skip sensitive file checks for major CDNs and protected sites
      const isProtectedSite = domain.includes('x.com') ||
                             domain.includes('twitter.com') ||
                             domain.includes('facebook.com') ||
                             domain.includes('google.com') ||
                             domain.includes('github.com') ||
                             domain.includes('cloudflare.com') ||
                             domain.includes('vercel.app') ||
                             domain.includes('netlify.app')

      if (isProtectedSite) {
        continue
      }

      // Only check if status indicates file might exist
      if (response.status === 200 || response.status === 403) {
        // Deep content validation to avoid false positives
        let contentText = ''
        let contentType = ''
        let contentLength = 0

        try {
          const fullResponse = await fetch(baseUrl + file, {
            method: 'GET',
            redirect: 'manual',
          })
          contentText = await fullResponse.text()
          contentType = fullResponse.headers.get('content-type') || ''
          contentLength = parseInt(fullResponse.headers.get('content-length') || '0')
        } catch {
          // If we can't fetch content, assume it's safe
          continue
        }

        // FALSE POSITIVE DETECTION ALGORITHMS

        // 1. Size check: Error pages are usually short
        if (contentLength > 0 && contentLength < 500) {
          continue // Too short, likely error page
        }

        // 2. HTML error page detection
        if (contentType.includes('text/html') || contentText.includes('<!DOCTYPE') || contentText.includes('<html')) {
          // Check for error page indicators
          const errorIndicators = [
            '404', 'not found', 'page not found', 'file not found',
            'error', 'bad request', 'oops', 'sorry',
            'access denied', 'forbidden', 'unauthorized', '403', '500',
            'internal server error', 'service unavailable',
            'temporarily unavailable', 'maintenance', 'coming soon',
            'under construction', 'redirect'
          ]

          const hasErrorIndicators = errorIndicators.some(indicator =>
            contentText.toLowerCase().includes(indicator.toLowerCase())
          )

          if (hasErrorIndicators) {
            continue // Error page detected
          }

          // Check for typical web page structure without sensitive content
          const hasWebStructure = contentText.includes('<body') ||
                                 contentText.includes('<div') ||
                                 contentText.includes('<head') ||
                                 contentText.includes('<meta') ||
                                 (contentText.includes('<title>') && contentText.includes('</title>'))

          if (hasWebStructure && !contentText.includes('=') && !contentText.includes('key') && !contentText.includes('secret')) {
            continue // Looks like a web page, not sensitive file
          }
        }

        // 3. Content validation for specific file types
        let isRealVulnerableFile = false

        if (file.includes('.env')) {
          // Check for environment variable syntax
          isRealVulnerableFile = /[A-Z_]+=.*/.test(contentText) ||
                                contentText.includes('key') ||
                                contentText.includes('secret') ||
                                contentText.includes('password') ||
                                contentText.includes('token')
        } else if (file.includes('.log')) {
          // Check for log file patterns
          isRealVulnerableFile = contentText.includes('error') ||
                                contentText.includes('info') ||
                                contentText.includes('debug') ||
                                /\d{4}-\d{2}-\d{2}/.test(contentText) // Date patterns
        } else if (file.includes('.git')) {
          // Check for git file patterns
          isRealVulnerableFile = contentText.includes('ref:') ||
                                contentText.includes('tree ') ||
                                contentText.includes('commit ') ||
                                contentText.includes('blob ')
        } else if (file.includes('.md') || file.includes('.txt')) {
          // For documentation files, check if they contain sensitive info
          isRealVulnerableFile = contentText.includes('password') ||
                                contentText.includes('secret') ||
                                contentText.includes('key') ||
                                contentLength > 1000 // Large documentation files
        } else {
          // For other files, if we got here and content is not HTML error, flag it
          isRealVulnerableFile = contentLength > 100 || contentText.length > 100
        }

        if (!isRealVulnerableFile) {
          continue // Not a real vulnerable file
        }

        // Determine severity based on file type and content
        let severity = 'MEDIUM'
        if (file.includes('.env') || file.includes('.git') || contentText.includes('password')) {
          severity = 'CRITICAL'
        } else if (file.includes('.log') || contentText.includes('secret') || contentText.includes('key')) {
          severity = 'HIGH'
        }

        issues.push({
          type: 'INFORMATION_DISCLOSURE',
          severity,
          title: `Sensitive File Exposed: ${file}`,
          description: `The file ${file} is accessible via web and contains sensitive information.`,
          recommendation: file.includes('.git')
            ? 'Delete .git folder from production or configure server to block .git access.'
            : file.includes('.env')
            ? 'Move .env files outside web root or configure server to deny access.'
            : file.includes('.log')
            ? 'Move log files outside web root or configure server to deny access.'
            : 'Configure server to deny access to sensitive files and documentation.',
          owaspCategory: 'A01',
          evidence: {
            url: baseUrl + file,
            status: response.status,
            contentType,
            contentLength,
            sample: contentText.substring(0, 200) + (contentText.length > 200 ? '...' : ''),
            detectionMethod: 'content_validation'
          }
        })
      }
    } catch (error) {
      // Network error or file doesn't exist - this is good
      continue
    }
  }

  return issues
}

// Vulnerability Scanner with Enhanced Hybrid Approach
async function scanVulnerabilities(url: string, domain: string) {
  const vulnerabilities: any[] = []

  // Skip vulnerability checks for major protected sites (but allow scanning our own site)
  const isProtectedSite = domain && typeof domain === 'string' && (
                         domain.includes('x.com') ||
                         domain.includes('twitter.com') ||
                         domain.includes('facebook.com') ||
                         domain.includes('google.com') ||
                         domain.includes('github.com') ||
                         domain.includes('cloudflare.com') ||
                         domain.includes('microsoft.com') ||
                         domain.includes('apple.com') ||
                         domain.includes('amazon.com') ||
                         domain.includes('linkedin.com') ||
                         domain.includes('instagram.com') ||
                         domain.includes('youtube.com') ||
                         domain.includes('reddit.com') ||
                         domain.includes('netflix.com') ||
                         domain.includes('spotify.com') ||
                         domain.includes('discord.com') ||
                         domain.includes('slack.com') ||
                         domain.includes('zoom.us') ||
                         domain.includes('dropbox.com') ||
                         domain.includes('notion.so') ||
                         domain.includes('figma.com') ||
                         domain.includes('canva.com') ||
                         domain.includes('stripe.com') ||
                         domain.includes('paypal.com') ||
                         domain.includes('shopify.com')
                        )

  if (isProtectedSite) {
    // Return minimal vulnerabilities for protected sites
    vulnerabilities.push({
      type: 'INFO',
      severity: 'INFO',
      title: 'Protected Site Detected',
      description: 'This is a major platform with enterprise-grade security. Standard vulnerability checks are not applicable.',
      recommendation: 'Major platforms have their own security teams and monitoring systems.',
      owaspCategory: 'N/A',
    })
    return vulnerabilities
  }

  try {
    // Fetch HTML content
    const response = await fetch(url)
    const html = await response.text()
    const headers = Object.fromEntries(response.headers.entries())

    // Detect if page is an error page (404, 403, 500) to avoid false positives
    const isErrorPage = [404, 403, 500, 502, 503].includes(response.status)
    const statusCode = response.status

    // 0. Check for missing security headers (Deduplication check)
    const seenTitles = new Set<string>()
    const criticalHeaders = [
      { name: 'content-security-policy', type: 'INSECURE_HEADERS' },
      { name: 'strict-transport-security', type: 'INSECURE_HEADERS' },
      { name: 'x-frame-options', type: 'INSECURE_HEADERS' },
      { name: 'x-content-type-options', type: 'INSECURE_HEADERS' },
    ]

    criticalHeaders.forEach(({ name, type }) => {
      if (!headers || !headers[name.toLowerCase()]) {
        const title = `Missing Security Header: ${name}`
        if (!seenTitles.has(title)) {
          const missingCSP = OWASP_PATTERNS_DB['missing-csp'] as any
          if (missingCSP && name === 'content-security-policy') {
            vulnerabilities.push({
              ...missingCSP,
              title,
              evidence: { url },
            })
          } else {
            vulnerabilities.push({
              type,
              severity: 'MEDIUM',
              title,
              description: `The ${name} header is not set, which can expose application to various security risks.`,
              recommendation: `Implement ${name} header with appropriate values for your application.`,
              owaspCategory: 'A05',
            })
          }
          seenTitles.add(title)
        }
      }
    })

    // 1. Check for libraries with CVEs using HYBRID approach
    const libraryPatterns = [
      { pattern: /jquery[-.](\d+\.?\d*\.?\d*)/gi, name: 'jQuery' },
      { pattern: /react[-.](\d+\.?\d*\.?\d*)/gi, name: 'React' },
      { pattern: /angular[-.](\d+\.?\d*\.?\d*)/gi, name: 'Angular' },
      { pattern: /vue[-.](\d+\.?\d*\.?\d*)/gi, name: 'Vue.js' },
      { pattern: /bootstrap[-.](\d+\.?\d*\.?\d*)/gi, name: 'Bootstrap' },
      { pattern: /lodash[-.](\d+\.?\d*\.?\d*)/gi, name: 'Lodash' },
      { pattern: /moment[-.](\d+\.?\d*\.?\d*)/gi, name: 'Moment.js' },
    ]

    for (const { pattern, name } of libraryPatterns) {
      const matches = html.match(pattern)
      if (matches) {
        for (const match of matches) {
          const versionMatch = match.match(/(\d+\.?\d*\.?\d*)/)
          if (versionMatch) {
            const version = versionMatch[1]

            // Check for CVEs using HYBRID approach
            const cveResult = await checkLibraryCVEsHybrid(name, version)

            if (cveResult.hasVulnerabilities && cveResult.details && cveResult.details[0]) {
              vulnerabilities.push({
                type: 'VULNERABLE_SOFTWARE',
                severity: cveResult.severity,
                title: `${name} ${version} has Known Vulnerabilities`,
                description: `Detected ${name} version ${version} with known security vulnerability.`,
                recommendation: `Update ${name} to the latest stable version immediately.`,
                owaspCategory: 'A06',
                evidence: {
                  library: name,
                  version: version,
                  ...cveResult.details[0],
                },
              })
            }
          }
        }
      }
    }

    // Skip sensitive file checks if page returned error (avoid noise on 404s)
    if (!isErrorPage) {
      // 2. Check for sensitive files exposure
      const sensitiveFileIssues = await checkSensitiveFiles(url, domain)
      vulnerabilities.push(...sensitiveFileIssues)
    }

    // 3. Check for information disclosure in comments
    const commentPatterns = [
      { pattern: /<!--\s*(TODO|FIXME|BUG|HACK):/gi, title: 'Development Comments in Production' },
      { pattern: /\/\*\*\s*@author/gi, title: 'Author Comments in Production' },
      { pattern: /<!--\s*(debug|test|staging)/gi, title: 'Debug/Development Indicators' },
    ]

    commentPatterns.forEach(({ pattern, title }) => {
      const matches = html.match(pattern)
      if (matches) {
        vulnerabilities.push({
          type: 'INFORMATION_DISCLOSURE',
          severity: 'LOW',
          title,
          description: `Found ${matches.length} occurrence(s) of development-related comments in HTML source.`,
          recommendation: 'Remove development comments and debugging information from production code.',
          owaspCategory: 'A01',
        })
      }
    })

    // 4. Check for inline event handlers (potential XSS vectors)
    const eventHandlerPatterns = [
      /on\w+\s*=\s*["'][^"']*["']/gi,
      /javascript:/gi,
    ]

    eventHandlerPatterns.forEach((pattern) => {
      const matches = html.match(pattern)
      if (matches && matches.length > 0) {
        const inlineHandlerPattern = OWASP_PATTERNS_DB['inline-event-handlers'] as any
        if (inlineHandlerPattern) {
          vulnerabilities.push({
            ...inlineHandlerPattern,
            evidence: { count: matches.length },
          })
        }
      }
    })

    // 5. Check for mixed content
    if (url.startsWith('https://')) {
      const httpResources = html.match(/http:\/\/[^"'\s>]+/gi)
      if (httpResources && httpResources.length > 0) {
        const mixedContentPattern = OWASP_PATTERNS_DB['http-on-https'] as any
        if (mixedContentPattern) {
          vulnerabilities.push({
            ...mixedContentPattern,
            evidence: { count: httpResources.length },
          })
        }
      }
    }

    // 6. Check for meta tags that can leak information
    const metaTagPatterns = [
      { pattern: /<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/gi, title: 'Meta Generator Tag' },
      { pattern: /<meta\s+name=["']author["']\s+content=["']([^"']+)["']/gi, title: 'Meta Author Tag' },
    ]

    metaTagPatterns.forEach(({ pattern, title }) => {
      const matches = html.match(pattern)
      if (matches) {
        vulnerabilities.push({
          type: 'INFORMATION_DISCLOSURE',
          severity: 'INFO',
          title,
          description: 'Meta tags can disclose information about technology stack or author.',
          recommendation: 'Consider removing unnecessary meta tags that disclose implementation details.',
          owaspCategory: 'A01',
        })
      }
    })

    // 7. Check for insecure forms
    const formPattern = /<form\s+[^>]*action=["']http:\/\//gi
    const insecureForms = html.match(formPattern)
    if (insecureForms && insecureForms.length > 0) {
      vulnerabilities.push({
        type: 'MISCONFIGURATION',
        severity: 'HIGH',
        title: 'Insecure Form Action Detected',
        description: `Found ${insecureForms.length} form(s) with HTTP action on HTTPS page. Form data will be sent unencrypted.`,
        recommendation: 'Update all form actions to use HTTPS to protect sensitive data in transit.',
        owaspCategory: 'A02',
        evidence: { count: insecureForms.length },
      })
    }

    // Skip referrer policy and Open Graph checks on error pages (noise reduction)
    if (!isErrorPage) {
      // 8. Check for missing referrer policy
      if (!headers['referrer-policy']) {
        const missingReferrer = OWASP_PATTERNS_DB['missing-x-content-type-options'] as any
        if (missingReferrer) {
          vulnerabilities.push({
            ...missingReferrer,
            title: 'Missing Referrer-Policy Header',
            evidence: { url },
          })
        }
      }

      // 9. Social Media Metadata Analysis (Open Graph)
      const socialIssues = analyzeSocialMetadata(html)
      vulnerabilities.push(...socialIssues)
    }

    // 10. Cookie Security Analysis
    const cookieIssues = analyzeCookies(headers, html)
    vulnerabilities.push(...cookieIssues)

    // 11. CORS Policy Analysis
    const corsIssues = analyzeCORS(headers)
    vulnerabilities.push(...corsIssues)

    // 12. SRI (Subresource Integrity) Check
    const sriIssues = checkSRI(html, url)
    vulnerabilities.push(...sriIssues)

    // 13. Content Injection Check
    const injectionIssues = checkContentInjection(html, url)
    vulnerabilities.push(...injectionIssues)

    // 14. WAF Detection
    const wafDetected = detectWAF(headers)
    if (wafDetected.length > 0) {
      wafDetected.forEach((waf: any) => {
        vulnerabilities.push({
          type: 'MISCONFIGURATION',
          severity: 'INFO',
          title: `WAF Detected: ${waf.name}`,
          description: `Website is protected by ${waf.name}. This is good for security.`,
          recommendation: 'Ensure WAF rules are regularly updated and tuned for your application.',
          evidence: { waf: waf.name },
        })
      })
    } else {
      vulnerabilities.push({
        type: 'MISCONFIGURATION',
        severity: 'MEDIUM',
        title: 'No WAF Detected',
        description: 'No Web Application Firewall detected. This may leave application vulnerable to automated attacks.',
        recommendation: 'Consider implementing a WAF (Cloudflare, AWS WAF, ModSecurity, etc.) to protect against common attacks.',
      })
    }

    // 15. SPA Pattern Detection (Next.js, React patterns)
    if (html.includes('data-nextjs-')) {
      const nextjsDataHref = SPA_PATTERNS_DB['nextjs-data-href'] as any
      if (nextjsDataHref) {
        vulnerabilities.push({
          ...nextjsDataHref,
          evidence: { url },
        })
      }
    }

    if (html.includes('__NEXT_DATA__')) {
      const nextjsBuildId = SPA_PATTERNS_DB['nextjs-build-id-leak'] as any
      if (nextjsBuildId) {
        vulnerabilities.push({
          ...nextjsBuildId,
          evidence: { url },
        })
      }
    }

    // Check for source map references
    const sourceMapPattern = /sourceMappingURL=|# sourceMappingURL=/gi
    if (sourceMapPattern.test(html)) {
      const sourceMapRef = SPA_PATTERNS_DB['source-map-reference'] as any
      if (sourceMapRef) {
        vulnerabilities.push({
          ...sourceMapRef,
          evidence: { url },
        })
      }
    }

    // Check for Webpack devtools exposure
    if (html.includes('__webpack_') || html.includes('webpack://')) {
      const webpackDevtools = SPA_PATTERNS_DB['webpack-devtools-exposed'] as any
      if (webpackDevtools) {
        vulnerabilities.push({
          ...webpackDevtools,
          evidence: { url },
        })
      }
    }

    return vulnerabilities
  } catch (error) {
    console.error('Vulnerability scan error:', error)
    vulnerabilities.push({
      type: 'OTHER',
      severity: 'INFO',
      title: 'Scan Incomplete',
      description: 'Could not complete full vulnerability scan due to errors.',
      recommendation: 'Ensure that website is accessible and try again.',
    })
  }

  return vulnerabilities
}

// Port Scanner (basic scan of common ports)
async function scanPorts(domain: string) {
  // Since we can't actually scan ports from Vercel, we'll do informational checks
  const portScans: any[] = []

  const commonPorts = [
    { port: 80, protocol: 'tcp', service: 'HTTP', risk: 'LOW', description: 'HTTP port - ensure HTTPS is used' },
    { port: 443, protocol: 'tcp', service: 'HTTPS', risk: 'INFO', description: 'HTTPS port - standard secure port' },
    { port: 22, protocol: 'tcp', service: 'SSH', risk: 'MEDIUM', description: 'SSH port - ensure strong authentication' },
    { port: 21, protocol: 'tcp', service: 'FTP', risk: 'HIGH', description: 'FTP port - consider using SFTP' },
  ]

  // Check if ports are accessible
  for (const portInfo of commonPorts) {
    try {
      const url = portInfo.port === 80 ? `http://${domain}` : `https://${domain}:${portInfo.port}`
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 2000)

      try {
        const response = await fetch(url, {
          method: 'HEAD',
          signal: controller.signal,
        })
        clearTimeout(timeoutId)

        portScans.push({
          ...portInfo,
          state: 'open',
        })
      } catch {
        clearTimeout(timeoutId)
        portScans.push({
          ...portInfo,
          state: 'filtered',
        })
      }
    } catch {
      portScans.push({
        ...portInfo,
        state: 'closed',
      })
    }
  }

  return portScans
}

// Main API Handler
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const url = searchParams.get('url')

  console.log('API scan request received for URL:', url)

  if (!url) {
    console.log('URL parameter is missing')
    return NextResponse.json({ error: 'URL parameter is required' }, { status: 400 })
  }

  const parsedUrl = parseUrl(url)
  if (!parsedUrl) {
    console.log('Invalid URL format:', url)
    return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 })
  }

  console.log('Parsed URL:', parsedUrl)

  try {
    // Check internet availability for enhanced mode
    const internetAvailable = await hasInternetAccess()
    console.log('Internet available:', internetAvailable)

    // Run all checks in parallel
    console.log('Starting parallel checks...')
    const [
      sslCheck,
      headersCheck,
      dnsCheck,
      performance,
      vulnerabilities,
      portScans,
    ] = await Promise.all([
      checkSSL(parsedUrl.domain),
      checkSecurityHeaders(url),
      checkDNS(parsedUrl.domain),
      checkPerformance(url),
      scanVulnerabilities(url, parsedUrl.domain),
      scanPorts(parsedUrl.domain),
    ])

    console.log('All checks completed')
    console.log('SSL Check:', sslCheck)
    console.log('Headers Check:', headersCheck)
    console.log('DNS Check:', dnsCheck)
    console.log('Performance Check:', performance)

    // Check if website is accessible
    const isAccessible = sslCheck.hasCertificate || sslCheck.isValid || performance.statusCode > 0

    if (!isAccessible) {
      console.log('Website is not accessible')
      return NextResponse.json({
        error: 'Website is not accessible. Please check URL and ensure that website is online.',
        details: {
          url: url,
          domain: parsedUrl.domain,
          sslIssue: sslCheck.issues.length > 0 ? sslCheck.issues[0] : null,
          performanceIssue: performance.recommendations.length > 0 ? performance.recommendations[0] : null,
        }
      }, { status: 400 })
    }

    // Calculate overall score
    const scores = [
      sslCheck.score,
      headersCheck.score,
      dnsCheck.score,
      performance.score,
    ]

    const averageScore = Math.round(
      scores.reduce((a, b) => a + b, 0) / scores.length
    )

    // Check if this is a protected site (but allow scanning our own secaudit-pi.vercel.app)
    const isProtectedSite = parsedUrl.domain.includes('x.com') ||
                           parsedUrl.domain.includes('twitter.com') ||
                           parsedUrl.domain.includes('facebook.com') ||
                           parsedUrl.domain.includes('google.com') ||
                           parsedUrl.domain.includes('github.com') ||
                           parsedUrl.domain.includes('cloudflare.com') ||
                           parsedUrl.domain.includes('microsoft.com') ||
                           parsedUrl.domain.includes('apple.com') ||
                           parsedUrl.domain.includes('amazon.com') ||
                           parsedUrl.domain.includes('linkedin.com') ||
                           parsedUrl.domain.includes('instagram.com') ||
                           parsedUrl.domain.includes('youtube.com') ||
                           parsedUrl.domain.includes('reddit.com') ||
                           parsedUrl.domain.includes('netflix.com') ||
                           parsedUrl.domain.includes('spotify.com') ||
                           parsedUrl.domain.includes('discord.com') ||
                           parsedUrl.domain.includes('slack.com') ||
                           parsedUrl.domain.includes('zoom.us') ||
                           parsedUrl.domain.includes('dropbox.com') ||
                           parsedUrl.domain.includes('notion.so') ||
                           parsedUrl.domain.includes('figma.com') ||
                           parsedUrl.domain.includes('canva.com') ||
                           parsedUrl.domain.includes('stripe.com') ||
                           parsedUrl.domain.includes('paypal.com') ||
                           parsedUrl.domain.includes('shopify.com')

    // Deduct points for critical and high severity vulnerabilities (skip for protected sites)
    let penalty = 0
    if (!isProtectedSite) {
      vulnerabilities.forEach((vuln) => {
        if (vuln.severity === 'CRITICAL') penalty += 20
        else if (vuln.severity === 'HIGH') penalty += 10
        else if (vuln.severity === 'MEDIUM') penalty += 5
      })
    }

    const overallScore = Math.max(0, averageScore - penalty)

    // Determine risk level
    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN' = 'UNKNOWN'
    if (overallScore < 20) riskLevel = 'CRITICAL'
    else if (overallScore < 40) riskLevel = 'HIGH'
    else if (overallScore < 60) riskLevel = 'MEDIUM'
    else if (overallScore < 80) riskLevel = 'LOW'
    else riskLevel = 'INFO'

    console.log('Calculated scores and risk level:', { averageScore, penalty, overallScore, riskLevel, internetAvailable })

    console.log('Preparing scan result...')

      // Create scan object for response (no database)
    const scan = {
      id: `scan-${Date.now()}`,
      url: url,
      domain: parsedUrl.domain,
      status: 'COMPLETED',
      overallScore,
      riskLevel,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      sslCheck: {
        ...sslCheck,
        issues: sslCheck.issues,
      },
      headersCheck: {
        ...headersCheck,
        missingHeaders: headersCheck.missingHeaders,
        issues: headersCheck.issues,
      },
      dnsCheck: {
        ...dnsCheck,
        dnsRecords: dnsCheck.dnsRecords,
        issues: Array.isArray(dnsCheck.dnsRecords) ? (dnsCheck.dnsRecords as any).issues : [],
      },
      performance: {
        ...performance,
        recommendations: performance.recommendations || [],
      },
      vulnerabilities: vulnerabilities.map((vuln) => ({
        ...vuln,
        evidence: vuln.evidence,
      })),
      portScans: portScans,
      internetAvailable,
      offlineMode: dnsCheck.offlineMode,
    }

    const response = {
      id: scan.id,
      url: scan.url,
      domain: scan.domain,
      status: scan.status,
      overallScore: scan.overallScore,
      riskLevel: scan.riskLevel,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      sslCheck: scan.sslCheck,
      headersCheck: scan.headersCheck,
      dnsCheck: {
        ...scan.dnsCheck,
        hasDNSSEC: scan.dnsCheck.hasDNSSEC,
        dnssecDetails: (scan.dnsCheck as any).dnssec,
      },
      performance: scan.performance,
      vulnerabilities: scan.vulnerabilities,
      portScans: scan.portScans,
      internetAvailable: scan.internetAvailable,
      offlineMode: scan.offlineMode,
    }

    console.log('Final response prepared:', response)

    return NextResponse.json(response)
  } catch (error) {
    console.error('Security scan error:', error)
    console.error('Error stack:', (error as Error).stack)
    return NextResponse.json(
      { error: 'Failed to perform security scan. The website might be inaccessible or there was a server error.' },
      { status: 500 }
    )
  }
}

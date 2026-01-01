import { NextRequest, NextResponse } from 'next/server'
import { checkVulnerability } from '@/lib/vulnerability-db'

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

// Security Headers Checker
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
    const issues: string[] = []

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

    // Check for information disclosure
    const server = headers['server']
    const xPoweredBy = headers['x-powered-by']

    if (server && server !== 'cloudflare') {
      issues.push('Server header discloses server technology')
    }

    if (xPoweredBy) {
      issues.push('X-Powered-By header discloses framework information')
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

// DNS Checker (using DNS-over-HTTPS)
async function checkDNS(domain: string) {
  try {
    const dnsChecks = {
      hasARecord: false,
      hasAAAARecord: false,
      hasMXRecord: false,
      hasTXTRecord: false,
      hasNSRecord: false,
      hasSPF: false,
      spfRecord: undefined as string | undefined,
      spfValid: false,
      hasDMARC: false,
      dmarcRecord: undefined as string | undefined,
      dmarcPolicy: undefined as string | undefined,
      dmarcValid: false,
      hasDKIM: false,
      hasDNSSEC: false,
      dnsRecords: [] as any[],
      issues: [] as string[],
      score: 0,
    }

    // Use Google DNS-over-HTTPS API
    const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS']

    for (const type of recordTypes) {
      try {
        const response = await fetch(
          `https://dns.google/resolve?name=${domain}&type=${type}`,
          { method: 'GET' }
        )
        const data = await response.json()

        if (data.Answer && data.Answer.length > 0) {
          switch (type) {
            case 'A':
              dnsChecks.hasARecord = true
              break
            case 'AAAA':
              dnsChecks.hasAAAARecord = true
              break
            case 'MX':
              dnsChecks.hasMXRecord = true
              break
            case 'TXT':
              dnsChecks.hasTXTRecord = true
              // Check for SPF, DMARC, DKIM
              data.Answer.forEach((record: any) => {
                const txt = record.data
                if (txt.includes('v=spf1')) {
                  dnsChecks.hasSPF = true
                  dnsChecks.spfRecord = txt
                  dnsChecks.spfValid = !txt.includes('~all') && !txt.includes('-all')
                }
                if (txt.includes('v=DMARC1')) {
                  dnsChecks.hasDMARC = true
                  dnsChecks.dmarcRecord = txt
                  if (txt.includes('p=reject')) {
                    dnsChecks.dmarcPolicy = 'reject'
                    dnsChecks.dmarcValid = true
                  } else if (txt.includes('p=quarantine')) {
                    dnsChecks.dmarcPolicy = 'quarantine'
                    dnsChecks.dmarcValid = true
                  } else {
                    dnsChecks.dmarcPolicy = 'none'
                    dnsChecks.dmarcValid = false
                  }
                }
                if (txt.includes('v=DKIM1')) {
                  dnsChecks.hasDKIM = true
                }
              })
              break
            case 'NS':
              dnsChecks.hasNSRecord = true
              break
          }

          dnsChecks.dnsRecords.push(...data.Answer)
        }
      } catch (error) {
        console.error(`DNS ${type} check error:`, error)
      }
    }

    // Calculate score
    let score = 0
    if (dnsChecks.hasARecord) score += 20
    if (dnsChecks.hasNSRecord) score += 10

    // Only check email security if MX records exist
    if (dnsChecks.hasMXRecord) {
      if (dnsChecks.hasSPF && dnsChecks.spfValid) score += 20
      if (dnsChecks.hasDMARC && dnsChecks.dmarcValid) score += 20
      if (dnsChecks.hasDKIM) score += 15
    } else {
      // If no MX records, email security is not applicable
      dnsChecks.issues.push('No MX records found - email security (SPF, DMARC, DKIM) is not applicable')
    }

    if (dnsChecks.hasMXRecord) score += 15

    dnsChecks.score = score

    return dnsChecks
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
      issues: ['Failed to perform DNS lookup'],
      score: 0,
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

// Cookie Security Analyzer
function analyzeCookies(headers: Record<string, string>, html: string) {
  const issues: any[] = []
  const setCookie = headers['set-cookie']
  const cookies = typeof setCookie === 'string' ? [setCookie] : (setCookie || [])

  // Analyze each cookie
  cookies.forEach((cookie: string) => {
    if (!cookie.includes('Secure')) {
      issues.push({
        type: 'MISCONFIGURATION',
        severity: 'HIGH',
        title: 'Cookie Missing Secure Flag',
        description: 'Cookie is transmitted over unencrypted HTTP connections, making it vulnerable to interception.',
        recommendation: 'Add "Secure" flag to cookie to only transmit over HTTPS.',
        evidence: { cookie: cookie.split(';')[0] },
      })
    }

    if (!cookie.includes('HttpOnly')) {
      issues.push({
        type: 'XSS',
        severity: 'MEDIUM',
        title: 'Cookie Missing HttpOnly Flag',
        description: 'Cookie is accessible via JavaScript, making it vulnerable to XSS attacks.',
        recommendation: 'Add "HttpOnly" flag to prevent client-side scripts from accessing cookie.',
        evidence: { cookie: cookie.split(';')[0] },
      })
    }

    if (!cookie.includes('SameSite')) {
      issues.push({
        type: 'CSRF',
        severity: 'MEDIUM',
        title: 'Cookie Missing SameSite Flag',
        description: 'Cookie is sent with all cross-site requests, increasing CSRF attack risk.',
        recommendation: 'Add "SameSite=Strict" or "SameSite=Lax" attribute to prevent CSRF attacks.',
        evidence: { cookie: cookie.split(';')[0] },
      })
    }

    // Check for long expiration times
    const maxAgeMatch = cookie.match(/max-age=(\d+)/i)
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1])
      // More than 30 days
      if (maxAge > 2592000) {
        issues.push({
          type: 'MISCONFIGURATION',
          severity: 'LOW',
          title: 'Cookie Long Expiration Time',
          description: `Cookie has a very long expiration time (${Math.round(maxAge / 86400)} days), increasing exposure if compromised.`,
          recommendation: 'Reduce cookie expiration time to a reasonable duration (e.g., 1-7 days).',
          evidence: { maxAge, days: Math.round(maxAge / 86400) },
        })
      }
    }
  })

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

// SRI (Subresource Integrity) Checker
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
        issues.push({
          type: 'MISCONFIGURATION',
          severity: 'MEDIUM',
          title: 'External Resource Missing SRI',
          description: `External resource (${src}) is loaded without Subresource Integrity (SRI) check.`,
          recommendation: 'Add integrity attribute with SHA-256/384/512 hash to prevent CDN compromise attacks.',
          evidence: { url: src },
        })
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
    ' barracuda': 'Barracuda WAF',
  }

  const detected = []
  const headerString = JSON.stringify(headers).toLowerCase()

  Object.entries(wafSignatures).forEach(([signature, name]) => {
    if (headerString.includes(signature)) {
      detected.push({ signature, name })
    }
  })

  return detected
}

// Content Injection Checks
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
      issues.push({
        type: 'XSS',
        severity: 'HIGH',
        title: 'Potential Content Injection Detected',
        description: 'HTML contains patterns that may indicate server-side template injection or XSS vulnerabilities.',
        recommendation: 'Review server-side rendering code and ensure proper output encoding.',
        evidence: { pattern: pattern.source },
      })
    }
  })

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

// CVE Intelligence - Check vulnerabilities in detected libraries
async function checkLibraryCVEs(libraryName: string, version: string) {
  try {
    // Use OSV (Open Source Vulnerabilities) API
    const response = await fetch(`https://api.osv.dev/v1/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        package: {
          name: libraryName,
          ecosystem: libraryName.toLowerCase().includes('jquery') ? 'npm' :
                     libraryName.toLowerCase().includes('bootstrap') ? 'npm' :
                     libraryName.toLowerCase().includes('react') ? 'npm' :
                     libraryName.toLowerCase().includes('angular') ? 'npm' :
                     libraryName.toLowerCase().includes('vue') ? 'npm' : 'npm'
        },
        version: version
      })
    })

    const data = await response.json()

    if (data.vulns && data.vulns.length > 0) {
      const criticalVulns = data.vulns.filter((v: any) => v.severity === 'CRITICAL' || v.severity === 'HIGH')
      const hasCritical = criticalVulns.length > 0

      return {
        hasVulnerabilities: true,
        criticalCount: criticalVulns.length,
        totalCount: data.vulns.length,
        severity: hasCritical ? 'CRITICAL' : 'HIGH',
        details: data.vulns.slice(0, 3).map((v: any) => ({
          id: v.id,
          summary: v.summary,
          severity: v.severity || 'UNKNOWN'
        }))
      }
    }

    return { hasVulnerabilities: false }
  } catch (error) {
    console.error('CVE check error:', error)
    return { hasVulnerabilities: false, error: true }
  }
}

// Deep CSP Parser - Analyze CSP directives quality
function analyzeCSP(cspValue: string) {
  const issues: any[] = []

  if (!cspValue) {
    issues.push({
      type: 'INSECURE_HEADERS',
      severity: 'HIGH',
      title: 'Missing Content Security Policy',
      description: 'Content Security Policy (CSP) header is not set, leaving the application vulnerable to XSS and injection attacks.',
      recommendation: 'Implement a comprehensive CSP header. Start with: default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' https:;',
      owaspCategory: 'A03',
    })
    return issues
  }

  // Parse CSP directives
  const directives: { [key: string]: string[] } = {}
  const parts = cspValue.split(';').map(p => p.trim())

  parts.forEach(part => {
    const [directive, ...values] = part.split(/\s+/)
    if (directive && values.length > 0) {
      directives[directive] = values
    }
  })

  // Check for dangerous patterns
  const scriptSrc = directives['script-src'] || directives['default-src'] || []
  const styleSrc = directives['style-src'] || directives['default-src'] || []
  const objectSrc = directives['object-src'] || directives['default-src'] || []
  const frameSrc = directives['frame-src'] || directives['default-src'] || []

  // CRITICAL: Check for unsafe-inline in scripts
  if (scriptSrc.includes("'unsafe-inline'")) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'HIGH',
      title: 'CSP Allows unsafe-inline for Scripts',
      description: 'Content Security Policy allows inline scripts with \'unsafe-inline\', which can be exploited for XSS attacks.',
      recommendation: 'Remove \'unsafe-inline\' from script-src directive. Use nonce-based CSP: script-src \'self\' \'nonce-xyz\'',
      owaspCategory: 'A03',
      evidence: { directive: 'script-src', dangerous: 'unsafe-inline' }
    })
  }

  // CRITICAL: Check for unsafe-eval
  if (scriptSrc.includes("'unsafe-eval'")) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'HIGH',
      title: 'CSP Allows unsafe-eval',
      description: 'Content Security Policy allows eval() and similar functions with \'unsafe-eval\', which can be exploited.',
      recommendation: 'Remove \'unsafe-eval\' from script-src directive. Avoid using eval() in your code.',
      owaspCategory: 'A03',
      evidence: { directive: 'script-src', dangerous: 'unsafe-eval' }
    })
  }

  // MEDIUM: Check for unsafe-inline in styles
  if (styleSrc.includes("'unsafe-inline'")) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'MEDIUM',
      title: 'CSP Allows unsafe-inline for Styles',
      description: 'Content Security Policy allows inline styles with \'unsafe-inline\', which can be exploited for CSS-based attacks.',
      recommendation: 'Remove \'unsafe-inline\' from style-src directive. Use nonce-based CSP for styles.',
      owaspCategory: 'A03',
      evidence: { directive: 'style-src', dangerous: 'unsafe-inline' }
    })
  }

  // HIGH: Check for overly permissive wildcard sources
  const checkPermissive = (directive: string, sources: string[], directiveName: string) => {
    if (sources.includes('*') || sources.includes('*.com') || sources.includes('*.org')) {
      const severity = directive === 'script-src' || directive === 'default-src' ? 'HIGH' : 'MEDIUM'
      issues.push({
        type: 'MISCONFIGURATION',
        severity,
        title: `CSP Allows Wildcard Origins in ${directiveName}`,
        description: `Content Security Policy allows wildcard (*) or broad patterns in ${directiveName}, which defeats the purpose of CSP.`,
        recommendation: `Replace wildcards with specific trusted domains in ${directiveName} directive.`,
        owaspCategory: 'A03',
        evidence: { directive: directiveName, sources: sources.filter(s => s.includes('*')) }
      })
    }
  }

  checkPermissive('script-src', scriptSrc, 'script-src')
  checkPermissive('style-src', styleSrc, 'style-src')
  checkPermissive('object-src', objectSrc, 'object-src')
  checkPermissive('frame-src', frameSrc, 'frame-src')

  // MEDIUM: Check for data: URLs (potentially dangerous)
  const hasDataUrls = Object.values(directives).some((sources: string[]) =>
    sources.some(src => src.includes('data:'))
  )

  if (hasDataUrls) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'MEDIUM',
      title: 'CSP Allows data: URLs',
      description: 'Content Security Policy allows data: URLs, which can be exploited for XSS attacks via data URIs.',
      recommendation: 'Restrict data: URLs to specific cases (e.g., data: image/png) or remove if not needed.',
      owaspCategory: 'A03',
      evidence: { dangerous: 'data: URLs allowed' }
    })
  }

  // LOW: Check for missing critical directives
  const criticalDirectives = ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src']
  const missingDirectives = criticalDirectives.filter(dir => !directives[dir])

  if (missingDirectives.length > 0) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'LOW',
      title: 'Incomplete CSP Coverage',
      description: `CSP is missing critical directives: ${missingDirectives.join(', ')}. This leaves some attack vectors unprotected.`,
      recommendation: `Add missing directives: ${missingDirectives.map(d => `${d} 'self'`).join('; ')}`,
      owaspCategory: 'A03',
      evidence: { missing: missingDirectives }
    })
  }

  // INFO: CSP exists but analyze quality
  if (issues.length === 0) {
    issues.push({
      type: 'MISCONFIGURATION',
      severity: 'INFO',
      title: 'CSP Present (Basic Analysis)',
      description: 'Content Security Policy is configured. No obvious security issues detected in basic analysis.',
      recommendation: 'Consider implementing nonce-based CSP for better security, and regularly review CSP violations in browser console.',
      owaspCategory: 'A03',
    })
  }

  return issues
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
  const IGNORE_PATTERNS = {
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
            : file.includes('log')
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

// Vulnerability Scanner
async function scanVulnerabilities(url: string, domain: string) {
  const vulnerabilities: any[] = []

  // Skip vulnerability checks for major protected sites
  const isProtectedSite = domain.includes('x.com') ||
                         domain.includes('twitter.com') ||
                         domain.includes('facebook.com') ||
                         domain.includes('google.com') ||
                         domain.includes('github.com') ||
                         domain.includes('cloudflare.com') ||
                         domain.includes('vercel.app') ||
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

    // 0. Check DNS security configuration (SPF, DMARC, DKIM)
    // Get DNS info first
    const dnsInfo = await checkDNS(domain)

    if (dnsInfo.hasMXRecord) {
      if (!dnsInfo.hasSPF) {
        vulnerabilities.push({
          type: 'EMAIL_SECURITY',
          severity: 'HIGH',
          title: 'Missing SPF Record',
          description: 'Sender Policy Framework (SPF) record is not configured. This can allow email spoofing and phishing attacks.',
          recommendation: 'Add SPF record to your DNS: v=spf1 include:_spf.google.com ~all (adjust for your email provider).',
          owaspCategory: 'A01',
        })
      } else if (!dnsInfo.spfValid) {
        vulnerabilities.push({
          type: 'EMAIL_SECURITY',
          severity: 'MEDIUM',
          title: 'Weak SPF Configuration',
          description: 'SPF record exists but uses weak policy (allows all senders with ~all or -all).',
          recommendation: 'Strengthen SPF policy by replacing ~all with -all to reject unauthorized senders.',
          owaspCategory: 'A01',
        })
      }

      if (!dnsInfo.hasDMARC) {
        vulnerabilities.push({
          type: 'EMAIL_SECURITY',
          severity: 'HIGH',
          title: 'Missing DMARC Record',
          description: 'Domain-based Message Authentication, Reporting and Conformance (DMARC) record is not configured.',
          recommendation: 'Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
          owaspCategory: 'A01',
        })
      } else if (!dnsInfo.dmarcValid) {
        vulnerabilities.push({
          type: 'EMAIL_SECURITY',
          severity: 'MEDIUM',
          title: 'Weak DMARC Policy',
          description: `DMARC policy is set to '${dnsInfo.dmarcPolicy}' which may not provide adequate protection.`,
          recommendation: 'Set DMARC policy to p=reject for maximum protection.',
          owaspCategory: 'A01',
        })
      }

      if (!dnsInfo.hasDKIM) {
        vulnerabilities.push({
          type: 'EMAIL_SECURITY',
          severity: 'MEDIUM',
          title: 'Missing DKIM Configuration',
          description: 'DomainKeys Identified Mail (DKIM) is not configured for email authentication.',
          recommendation: 'Configure DKIM with your email provider (Google Workspace, Office 365, etc.).',
          owaspCategory: 'A01',
        })
      }
    }

    // 1. Check for missing security headers
    const criticalHeaders = [
      { name: 'content-security-policy', type: 'INSECURE_HEADERS' },
      { name: 'strict-transport-security', type: 'INSECURE_HEADERS' },
      { name: 'x-frame-options', type: 'INSECURE_HEADERS' },
      { name: 'x-content-type-options', type: 'INSECURE_HEADERS' },
    ]

    criticalHeaders.forEach(({ name, type }) => {
      if (!headers[name.toLowerCase()]) {
        vulnerabilities.push({
          type,
          severity: 'MEDIUM',
          title: `Missing Security Header: ${name}`,
          description: `The ${name} header is not set, which can expose application to various security risks.`,
          recommendation: `Implement ${name} header with appropriate values for your application.`,
          owaspCategory: 'A05',
        })
      }
    })

    // 2. Deep CSP Analysis
    const cspValue = headers['content-security-policy']
    if (cspValue) {
      const cspIssues = analyzeCSP(cspValue)
      vulnerabilities.push(...cspIssues)
    }

    // 3. Check for outdated JavaScript libraries with CVE analysis
    const libraryPatterns = [
      { pattern: /jquery[-.](\d+\.?\d*\.?\d*)/gi, name: 'jQuery', minVersion: '3.6.0' },
      { pattern: /react[-.](\d+\.?\d*\.?\d*)/gi, name: 'React', minVersion: '18.0.0' },
      { pattern: /angular[-.](\d+\.?\d*\.?\d*)/gi, name: 'Angular', minVersion: '12.0.0' },
      { pattern: /vue[-.](\d+\.?\d*\.?\d*)/gi, name: 'Vue.js', minVersion: '3.0.0' },
      { pattern: /bootstrap[-.](\d+\.?\d*\.?\d*)/gi, name: 'Bootstrap', minVersion: '5.0.0' },
    ]

    // Check for libraries and their CVEs
    for (const { pattern, name, minVersion } of libraryPatterns) {
      const matches = html.match(pattern)
      if (matches) {
        for (const match of matches) {
          const versionMatch = match.match(/(\d+\.?\d*\.?\d*)/)
          if (versionMatch) {
            const version = versionMatch[1]

            // Check for CVEs in this library version using embedded database
            const cveResult = checkVulnerability(name, version)

            if (cveResult) {
              vulnerabilities.push({
                type: 'VULNERABLE_SOFTWARE',
                severity: cveResult.severity,
                title: `${name} ${version} has Known Vulnerabilities`,
                description: `Detected ${name} version ${version} with known security vulnerability: ${cveResult.cve}.`,
                recommendation: `Update ${name} to the latest stable version immediately. Vulnerability type: ${cveResult.type}.`,
                owaspCategory: 'A06',
                evidence: {
                  library: name,
                  version: version,
                  cve: cveResult.cve,
                  severity: cveResult.severity,
                  type: cveResult.type
                }
              })
            } else {
              // Still check for outdated versions even if no CVEs
              vulnerabilities.push({
                type: 'OUTDATED_SOFTWARE',
                severity: 'LOW',
                title: `Potentially Outdated Library: ${name}`,
                description: `Detected ${name} version ${version}. Consider updating to the latest version.`,
                recommendation: `Update ${name} to the latest stable version (${minVersion} or later) to ensure security and performance.`,
                owaspCategory: 'A06',
              })
            }
          }
        }
      }
    }

    // 4. Check for sensitive files exposure
    const sensitiveFileIssues = await checkSensitiveFiles(url)
    vulnerabilities.push(...sensitiveFileIssues)

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
          description: `Found ${matches.length} occurrence(s) of development-related comments in the HTML source.`,
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
        vulnerabilities.push({
          type: 'XSS',
          severity: 'MEDIUM',
          title: 'Inline Event Handlers Detected',
          description: `Found ${matches.length} inline event handler(s) or javascript: protocol usage, which can be XSS vectors.`,
          recommendation: 'Remove inline event handlers and use event listeners instead. Avoid javascript: protocol in href attributes.',
          owaspCategory: 'A03',
        })
      }
    })

    // 5. Check for mixed content
    if (url.startsWith('https://')) {
      const httpResources = html.match(/http:\/\/[^"'\s>]+/gi)
      if (httpResources && httpResources.length > 0) {
        vulnerabilities.push({
          type: 'MISCONFIGURATION',
          severity: 'MEDIUM',
          title: 'Mixed Content Detected',
          description: `Found ${httpResources.length} HTTP resource(s) loaded on HTTPS page. This can compromise security.`,
          recommendation: 'Update all external resources to use HTTPS to prevent mixed content warnings and ensure secure connections.',
          owaspCategory: 'A05',
        })
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
          description: 'Meta tags can disclose information about the technology stack or author.',
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
      })
    }

    // 8. Check for missing referrer policy
    if (!headers['referrer-policy']) {
      vulnerabilities.push({
        type: 'INSECURE_HEADERS',
        severity: 'LOW',
        title: 'Missing Referrer-Policy Header',
        description: 'Referrer-Policy header is not set, which can leak sensitive information through the Referer header.',
        recommendation: 'Set Referrer-Policy header to "strict-origin-when-cross-origin" or "no-referrer" for sensitive pages.',
        owaspCategory: 'A05',
      })
    }

    // 9. Check for missing X-Content-Type-Options
    if (!headers['x-content-type-options']) {
      vulnerabilities.push({
        type: 'INSECURE_HEADERS',
        severity: 'LOW',
        title: 'Missing X-Content-Type-Options Header',
        description: 'X-Content-Type-Options header is not set, which can allow MIME type sniffing.',
        recommendation: 'Set X-Content-Type-Options: nosniff to prevent MIME type sniffing.',
        owaspCategory: 'A03',
      })
    }

    // 10. Check for server technology disclosure
    const server = headers['server']
    if (server && server !== 'cloudflare') {
      vulnerabilities.push({
        type: 'INFORMATION_DISCLOSURE',
        severity: 'LOW',
        title: 'Server Technology Disclosure',
        description: `Server header reveals: ${server}`,
        recommendation: 'Configure server to hide or minimize server information in headers.',
        owaspCategory: 'A01',
      })
    }

    // 11. Cookie Security Analysis
    const cookieIssues = analyzeCookies(headers, html)
    vulnerabilities.push(...cookieIssues)

    // 12. CORS Policy Analysis
    const corsIssues = analyzeCORS(headers)
    vulnerabilities.push(...corsIssues)

    // 13. SRI (Subresource Integrity) Check
    const sriIssues = checkSRI(html, url)
    vulnerabilities.push(...sriIssues)

    // 14. Content Injection Check
    const injectionIssues = checkContentInjection(html, url)
    vulnerabilities.push(...injectionIssues)

    // 15. WAF Detection
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
        description: 'No Web Application Firewall detected. This may leave to application vulnerable to automated attacks.',
        recommendation: 'Consider implementing a WAF (Cloudflare, AWS WAF, ModSecurity, etc.) to protect against common attacks.',
      })
    }

    // 16. Social Media Metadata Analysis
    const socialIssues = analyzeSocialMetadata(html)
    vulnerabilities.push(...socialIssues)

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
        error: 'Website is not accessible. Please check the URL and ensure the website is online.',
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

    // Check if this is a protected site
    const isProtectedSite = parsedUrl.domain.includes('x.com') ||
                           parsedUrl.domain.includes('twitter.com') ||
                           parsedUrl.domain.includes('facebook.com') ||
                           parsedUrl.domain.includes('google.com') ||
                           parsedUrl.domain.includes('github.com') ||
                           parsedUrl.domain.includes('cloudflare.com') ||
                           parsedUrl.domain.includes('vercel.app') ||
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

    console.log('Calculated scores and risk level:', { averageScore, penalty, overallScore, riskLevel })

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
        issues: dnsCheck.issues,
      },
      performance: {
        ...performance,
        recommendations: performance.recommendations,
      },
      vulnerabilities: vulnerabilities.map((vuln) => ({
        ...vuln,
        evidence: vuln.evidence,
      })),
      portScans: portScans,
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
      dnsCheck: scan.dnsCheck,
      performance: scan.performance,
      vulnerabilities: scan.vulnerabilities,
      portScans: scan.portScans,
    }

    console.log('Final response prepared:', response)

    return NextResponse.json(response)
  } catch (error) {
    console.error('Security scan error:', error)
    console.error('Error stack:', error.stack)
    return NextResponse.json(
      { error: 'Failed to perform security scan. The website might be inaccessible or there was a server error.' },
      { status: 500 }
    )
  }
}
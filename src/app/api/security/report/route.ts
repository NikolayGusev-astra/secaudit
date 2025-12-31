import { NextRequest, NextResponse } from 'next/server'

function generateMarkdownReport(scan: any) {
  const date = new Date().toLocaleDateString('ru-RU', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })

  const critical = scan.vulnerabilities?.filter((v: any) => v.severity === 'CRITICAL') || []
  const high = scan.vulnerabilities?.filter((v: any) => v.severity === 'HIGH') || []
  const medium = scan.vulnerabilities?.filter((v: any) => v.severity === 'MEDIUM') || []
  const low = scan.vulnerabilities?.filter((v: any) => v.severity === 'LOW') || []
  const info = scan.vulnerabilities?.filter((v: any) => v.severity === 'INFO') || []

  let report = `# 🛡️ Security Audit Report

---

## 📋 Executive Summary

**Target URL:** ${scan.url}
**Domain:** ${scan.domain}
**Scan Date:** ${date}
**Overall Score:** ${scan.overallScore}/100
**Risk Level:** ${scan.riskLevel}

---

## 📊 Security Scores by Category

| Category | Score | Status |
|-----------|--------|--------|
| SSL/TLS | ${scan.sslCheck?.score || 0}/100 | ${scan.sslCheck?.score >= 80 ? '✅ Good' : scan.sslCheck?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |
| Security Headers | ${scan.headersCheck?.score || 0}/100 | ${scan.headersCheck?.score >= 80 ? '✅ Good' : scan.headersCheck?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |
| DNS Security | ${scan.dnsCheck?.score || 0}/100 | ${scan.dnsCheck?.score >= 80 ? '✅ Good' : scan.dnsCheck?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |
| Performance | ${scan.performance?.score || 0}/100 | ${scan.performance?.score >= 80 ? '✅ Good' : scan.performance?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |

---

## 🔴 Critical Vulnerabilities (${critical.length})

${critical.length === 0 ? '✅ No critical vulnerabilities found' : critical.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
**OWASP Category:** ${v.owaspCategory || 'N/A'}
`).join('\n')}

---

## 🟠 High Severity Vulnerabilities (${high.length})

${high.length === 0 ? '✅ No high severity vulnerabilities found' : high.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
**OWASP Category:** ${v.owaspCategory || 'N/A'}
`).join('\n')}

---

## 🟡 Medium Severity Vulnerabilities (${medium.length})

${medium.length === 0 ? '✅ No medium severity vulnerabilities found' : medium.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
`).join('\n')}

---

## 🟢 Low Severity Vulnerabilities (${low.length})

${low.length === 0 ? '✅ No low severity vulnerabilities found' : low.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
`).join('\n')}

---

## ℹ️ Informational Messages (${info.length})

${info.length === 0 ? '✅ No informational messages' : info.map((v: any, i: number) => `
### ${i + 1}. ${v.title}
**Description:** ${v.description}
`).join('\n')}

---

## 🔒 SSL/TLS Analysis

${scan.sslCheck ? `
| Parameter | Value | Status |
|-----------|-------|--------|
| SSL Certificate | ${scan.sslCheck.hasCertificate ? '✅ Present' : '❌ Absent'} | ${scan.sslCheck.hasCertificate ? 'OK' : 'CRITICAL'} |
| Valid | ${scan.sslCheck.isValid ? '✅ Valid' : '❌ Invalid'} | ${scan.sslCheck.isValid ? 'OK' : 'CRITICAL'} |
| TLS Version | ${scan.sslCheck.tlsVersion || 'N/A'} | ${['TLS 1.2', 'TLS 1.3'].includes(scan.sslCheck.tlsVersion || '') ? 'OK' : 'WARNING'} |
| Self-Signed | ${scan.sslCheck.isSelfSigned ? '❌ Yes' : '✅ No'} | ${scan.sslCheck.isSelfSigned ? 'WARNING' : 'OK'} |
| Expired | ${scan.sslCheck.isExpired ? '❌ Yes' : '✅ No'} | ${scan.sslCheck.isExpired ? 'CRITICAL' : 'OK'} |

**Issues:**
${scan.sslCheck.issues && Array.isArray(scan.sslCheck.issues) && scan.sslCheck.issues.length > 0 ? scan.sslCheck.issues.map((issue: string) => `- ${issue}`).join('\n') : '✅ No issues found'}
` : '❌ SSL check not performed'}

---

## 📋 Security Headers Analysis

${scan.headersCheck ? `
| Header | Status |
|--------|--------|
| Content-Security-Policy (CSP) | ${scan.headersCheck.hasCSP ? '✅' : '❌'} |
| Strict-Transport-Security (HSTS) | ${scan.headersCheck.hasHSTS ? '✅' : '❌'} |
| X-Frame-Options | ${scan.headersCheck.hasXFrameOptions ? '✅' : '❌'} |
| X-Content-Type-Options | ${scan.headersCheck.hasXContentTypeOptions ? '✅' : '❌'} |
| X-XSS-Protection | ${scan.headersCheck.hasXSSProtection ? '✅' : '❌'} |
| Referrer-Policy | ${scan.headersCheck.hasReferrerPolicy ? '✅' : '❌'} |
| Permissions-Policy | ${scan.headersCheck.hasPermissionsPolicy ? '✅' : '❌'} |

**Missing Headers:**
${scan.headersCheck.missingHeaders && Array.isArray(scan.headersCheck.missingHeaders) && scan.headersCheck.missingHeaders.length > 0 ? scan.headersCheck.missingHeaders.map((h: string) => `- ${h}`).join('\n') : '✅ All headers configured'}

**Detected Issues:**
${scan.headersCheck.issues && Array.isArray(scan.headersCheck.issues) && scan.headersCheck.issues.length > 0 ? scan.headersCheck.issues.map((issue: string) => `- ${issue}`).join('\n') : '✅ No issues found'}
` : '❌ Security headers check not performed'}

---

## 🌐 DNS Security Analysis

${scan.dnsCheck ? `
| Parameter | Status |
|-----------|--------|
| SPF Record | ${scan.dnsCheck.hasSPF ? '✅' : '❌'} |
| DMARC | ${scan.dnsCheck.hasDMARC ? '✅' : '❌'} |
| DKIM | ${scan.dnsCheck.hasDKIM ? '✅' : '❌'} |
| DNSSEC | ${scan.dnsCheck.hasDNSSEC ? '✅' : '❌'} |

**DMARC Policy:**
${scan.dnsCheck.hasDMARC ? `
- Policy: ${scan.dnsCheck.dmarcPolicy}
- Valid: ${scan.dnsCheck.dmarcValid ? '✅ Valid' : '❌ Invalid'}
` : '❌ DMARC not configured'}

**Issues:**
${scan.dnsCheck.issues && Array.isArray(scan.dnsCheck.issues) && scan.dnsCheck.issues.length > 0 ? scan.dnsCheck.issues.map((issue: string) => `- ${issue}`).join('\n') : '✅ No issues found'}
` : '❌ DNS check not performed'}

---

## ⚡ Performance Analysis

${scan.performance ? `
| Metric | Value | Status |
|--------|-------|--------|
| HTTP Status | ${scan.performance.statusCode} | ${scan.performance.statusCode === 200 ? 'OK' : 'WARNING'} |
| Response Time | ${scan.performance.responseTime}ms | ${scan.performance.responseTime < 500 ? 'OK' : scan.performance.responseTime < 1000 ? 'WARNING' : 'CRITICAL'} |
| TTFB | ${scan.performance.ttfb || 'N/A'}ms | ${scan.performance.ttfb && scan.performance.ttfb < 200 ? 'OK' : 'WARNING'} |
| HTTP Version | ${scan.performance.httpVersion || 'N/A'} | ${['HTTP/2', 'HTTP/3'].includes(scan.performance.httpVersion || '') ? 'OK' : 'WARNING'} |
| GZIP Compression | ${scan.performance.hasGzip ? '✅' : '❌'} | ${scan.performance.hasGzip ? 'OK' : 'WARNING'} |
| Brotli Compression | ${scan.performance.hasBrotli ? '✅' : '❌'} | ${scan.performance.hasBrotli ? 'OK' : 'INFO'} |
| Cache-Control | ${scan.performance.hasCacheControl ? '✅' : '❌'} | ${scan.performance.hasCacheControl ? 'OK' : 'WARNING'} |
| ETag | ${scan.performance.hasETag ? '✅' : '❌'} | ${scan.performance.hasETag ? 'OK' : 'WARNING'} |

**Performance Recommendations:**
${scan.performance.recommendations && Array.isArray(scan.performance.recommendations) && scan.performance.recommendations.length > 0 ? scan.performance.recommendations.map((rec: string) => `- ${rec}`).join('\n') : '✅ No recommendations'}
` : '❌ Performance check not performed'}

---

## 🌐 Open Ports Analysis

${scan.portScans && scan.portScans.length > 0 ? `
| Port | Protocol | Service | State | Risk |
|------|----------|---------|--------|------|
${scan.portScans.map((port: any) => `| ${port.port} | ${port.protocol} | ${port.service} | ${port.state} | ${port.risk} |`).join('\n')}
` : '❌ Port scan not performed'}

---

## 📚 Additional Learning Resources

### OWASP Resources:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Security Tools:
- [OWASP ZAP](https://www.zaproxy.org/) - Free security scanner
- [Burp Suite](https://portswigger.net/burp) - Professional testing tool
- [Nmap](https://nmap.org/) - Network scanner
- [Nikto](https://www.cirt.net/Nikto2) - Web server scanner

### Learning Platforms:
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Hacker101](https://www.hacker101.com/)
- [PentesterLab](https://www.pentesterlab.com/)

### Certifications:
- [OSCP](https://www.offensive-security.com/penetration-testing-with-kali-linux/)
- [CEH](https://www.eccouncil.org/programs/certified-ethical-hacker/)
- [CISSP](https://www.isc2.org/certifications/cissp/)

---

## 📝 Next Steps & Recommendations

### Immediate Actions (CRITICAL):
${critical.length > 0 ? critical.map((v: any) => `- Fix: ${v.title}`).join('\n') : '- No critical vulnerabilities'}

### Priority Actions (HIGH):
${high.length > 0 ? high.map((v: any) => `- Fix: ${v.title}`).join('\n') : '- No high severity vulnerabilities'}

### Planned Actions (MEDIUM/LOW):
${[...medium, ...low].length > 0 ? [...medium, ...low].map((v: any) => `- Fix: ${v.title}`).join('\n') : '- No medium or low severity vulnerabilities'}

### Monitoring:
- Regularly scan website (monthly)
- Monitor dependency updates
- Subscribe to security bulletins
- Set up automated notifications

### Training:
- Study OWASP Top 10
- Practice on test websites
- Read security blogs and research

---

## 📞 Support & Contact

If you have questions about this report or need help fixing vulnerabilities:

- 📧 Email: security@example.com
- 💬 Discord: #security-help
- 📚 Wiki: https://wiki.example.com/security
- 🐛 Issues: https://github.com/example/security-audit/issues

---

*Report generated automatically by Security Audit Pro*
*${date}*
`

  return report
}

export async function POST(request: NextRequest) {
  console.log('=== API REPORT REQUEST ===')
  console.log('Report generation request received')

  try {
    const scanData = await request.json()

    console.log('📋 Received scan data for report generation')
    console.log('📊 Scan data summary:', {
      id: scanData.id,
      url: scanData.url,
      domain: scanData.domain,
      overallScore: scanData.overallScore,
      riskLevel: scanData.riskLevel,
      vulnerabilitiesCount: scanData.vulnerabilities?.length || 0,
      sslCheck: !!scanData.sslCheck,
      headersCheck: !!scanData.headersCheck,
      dnsCheck: !!scanData.dnsCheck,
      performance: !!scanData.performance,
      portScansCount: scanData.portScans?.length || 0,
    })

    if (!scanData || !scanData.id || !scanData.url) {
      console.log('❌ Invalid scan data provided')
      return NextResponse.json(
        { error: 'Invalid scan data', details: 'Scan data must include id, url, and domain' },
        { status: 400 }
      )
    }

    console.log('📝 Generating markdown report...')
    const markdown = generateMarkdownReport(scanData)
    const filename = `security-report-${scanData.domain}-${new Date().toISOString().split('T')[0]}.md`

    console.log('✅ Report generated successfully')
    console.log('📄 Report filename:', filename)
    console.log('📏 Report length:', markdown.length, 'characters')

    return new NextResponse(markdown, {
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    })
  } catch (error) {
    console.error('💥 Report generation error:', error)
    console.error('🔍 Error stack:', error.stack)
    console.error('🔍 Error details:', {
      name: error.name,
      message: error.message,
      code: error.code,
    })

    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred'
    return NextResponse.json(
      {
        error: 'Failed to generate report',
        details: errorMessage
      },
      { status: 500 }
    )
  }
}
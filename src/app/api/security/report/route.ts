import { NextRequest, NextResponse } from 'next/server'
import { SecurityReportEnricher } from '@/lib/security-report-enricher'
import { translations } from '@/lib/i18n'
import type { Language } from '@/lib/i18n'

function generateMarkdownReport(scan: any, language: Language = 'en') {
  const t = translations[language]
  const locale = language === 'ru' ? 'ru-RU' : 'en-US'
  const date = new Date().toLocaleDateString(locale, {
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

  let report = `# 🛡️ ${t.securityResults}

---

## 📋 ${language === 'ru' ? 'Исполнительное резюме' : 'Executive Summary'}

**${t.target}:** ${scan.url}
**${t.domain || 'Domain'}:** ${scan.domain}
**${language === 'ru' ? 'Дата сканирования' : 'Scan Date'}:** ${date}
**${t.securityScore}:** ${scan.overallScore}/100
**${language === 'ru' ? 'Уровень риска' : 'Risk Level'}:** ${scan.riskLevel}

---

## 📊 ${language === 'ru' ? 'Оценки безопасности по категориям' : 'Security Scores by Category'}

| ${language === 'ru' ? 'Категория' : 'Category'} | ${language === 'ru' ? 'Оценка' : 'Score'} | ${language === 'ru' ? 'Статус' : 'Status'} |
|-----------|--------|--------|
| ${t.sslTls} | ${scan.sslCheck?.score || 0}/100 | ${scan.sslCheck?.score >= 80 ? '✅ Good' : scan.sslCheck?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |
| ${t.securityHeaders} | ${scan.headersCheck?.score || 0}/100 | ${scan.headersCheck?.score >= 80 ? '✅ Good' : scan.headersCheck?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |
| ${t.dnsSecurityCategory} | ${scan.dnsCheck?.score || 0}/100 | ${scan.dnsCheck?.score >= 80 ? '✅ Good' : scan.dnsCheck?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |
| ${t.perfCategory} | ${scan.performance?.score || 0}/100 | ${scan.performance?.score >= 80 ? '✅ Good' : scan.performance?.score >= 60 ? '⚠️ Fair' : '❌ Poor'} |

---

## 🔴 ${language === 'ru' ? 'Критические уязвимости' : 'Critical Vulnerabilities'} (${critical.length})

${critical.length === 0 ? '✅ ' + (language === 'ru' ? 'Критические уязвимости не найдены' : 'No critical vulnerabilities found') : critical.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type || 'MISCELLANEOUS'}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
**OWASP Category:** ${v.owaspCategory || 'N/A'}
`).join('\n')}

---

## 🟠 ${language === 'ru' ? 'Уязвимости высокой степени' : 'High Severity Vulnerabilities'} (${high.length})

${high.length === 0 ? '✅ ' + (language === 'ru' ? 'Уязвимости высокой степени не найдены' : 'No high severity vulnerabilities found') : high.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type || 'MISCELLANEOUS'}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
**OWASP Category:** ${v.owaspCategory || 'N/A'}
`).join('\n')}

---

## 🟡 ${language === 'ru' ? 'Уязвимости средней степени' : 'Medium Severity Vulnerabilities'} (${medium.length})

${medium.length === 0 ? '✅ ' + (language === 'ru' ? 'Уязвимости средней степени не найдены' : 'No medium severity vulnerabilities found') : medium.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type || 'MISCELLANEOUS'}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
`).join('\n')}

---

## 🟢 ${language === 'ru' ? 'Уязвимости низкой степени' : 'Low Severity Vulnerabilities'} (${low.length})

${low.length === 0 ? '✅ ' + (language === 'ru' ? 'Уязвимости низкой степени не найдены' : 'No low severity vulnerabilities found') : low.map((v: any, i: number) => `
### ${i + 1}. ${v.title}

**Type:** ${v.type || 'MISCELLANEOUS'}
**Description:** ${v.description}
**Recommendation:** ${v.recommendation}
`).join('\n')}

---

## ℹ️ ${language === 'ru' ? 'Информационные сообщения' : 'Informational Messages'} (${info.length})

${info.length === 0 ? '✅ ' + (language === 'ru' ? 'Информационные сообщения отсутствуют' : 'No informational messages') : info.map((v: any, i: number) => `
### ${i + 1}. ${v.title}
**Description:** ${v.description}
`).join('\n')}

---

## 🔒 ${language === 'ru' ? 'Анализ SSL/TLS' : 'SSL/TLS Analysis'}

${scan.sslCheck ? `
| ${language === 'ru' ? 'Параметр' : 'Parameter'} | ${language === 'ru' ? 'Значение' : 'Value'} | ${language === 'ru' ? 'Статус' : 'Status'} |
|-----------|-------|--------|
| ${t.certificatePresent} | ${scan.sslCheck.hasCertificate ? '✅ ' + t.yes : '❌ ' + t.no} | ${scan.sslCheck.hasCertificate ? 'OK' : 'CRITICAL'} |
| ${t.certificateValid} | ${scan.sslCheck.isValid ? '✅ ' + t.yes : '❌ ' + t.no} | ${scan.sslCheck.isValid ? 'OK' : 'CRITICAL'} |
| ${t.tlsVersion} | ${scan.sslCheck.tlsVersion || 'N/A'} | ${['TLS 1.2', 'TLS 1.3'].includes(scan.sslCheck.tlsVersion || '') ? 'OK' : 'WARNING'} |
| Self-Signed | ${scan.sslCheck.isSelfSigned ? '❌ Yes' : '✅ No'} | ${scan.sslCheck.isSelfSigned ? 'WARNING' : 'OK'} |
| Expired | ${scan.sslCheck.isExpired ? '❌ Yes' : '✅ No'} | ${scan.sslCheck.isExpired ? 'CRITICAL' : 'OK'} |

**${language === 'ru' ? 'Проблемы' : 'Issues'}:**
${scan.sslCheck.issues && Array.isArray(scan.sslCheck.issues) && scan.sslCheck.issues.length > 0 ? scan.sslCheck.issues.map((issue: string) => `- ${issue}`).join('\n') : '✅ ' + (language === 'ru' ? 'Проблемы не найдены' : 'No issues found')}
` : '❌ ' + (language === 'ru' ? 'Проверка SSL не выполнена' : 'SSL check not performed')}

---

## 📋 ${language === 'ru' ? 'Анализ Security Headers' : 'Security Headers Analysis'}

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

**${t.missingHeaders}:**
${scan.headersCheck.missingHeaders && Array.isArray(scan.headersCheck.missingHeaders) && scan.headersCheck.missingHeaders.length > 0 ? scan.headersCheck.missingHeaders.map((h: string) => `- ${h}`).join('\n') : '✅ ' + (language === 'ru' ? 'Все заголовки настроены' : 'All headers configured')}

**${language === 'ru' ? 'Обнаруженные проблемы' : 'Detected Issues'}:**
${scan.headersCheck.issues && Array.isArray(scan.headersCheck.issues) && scan.headersCheck.issues.length > 0 ? scan.headersCheck.issues.map((issue: any) => {
  if (typeof issue === 'string') return `- ${issue}`
  else return `- ${issue.title || issue.description || JSON.stringify(issue)}`
}).join('\n') : '✅ ' + (language === 'ru' ? 'Проблемы не найдены' : 'No issues found')}
` : '❌ ' + (language === 'ru' ? 'Проверка заголовков безопасности не выполнена' : 'Security headers check not performed')}

---

## 🌐 ${language === 'ru' ? 'Анализ DNS безопасности' : 'DNS Security Analysis'}

${scan.dnsCheck ? `
| ${language === 'ru' ? 'Параметр' : 'Parameter'} | ${language === 'ru' ? 'Статус' : 'Status'} |
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

**${language === 'ru' ? 'Проблемы' : 'Issues'}:**
${scan.dnsCheck.issues && Array.isArray(scan.dnsCheck.issues) && scan.dnsCheck.issues.length > 0 ? scan.dnsCheck.issues.map((issue: string) => `- ${issue}`).join('\n') : '✅ ' + (language === 'ru' ? 'Проблемы не найдены' : 'No issues found')}
` : '❌ ' + (language === 'ru' ? 'Проверка DNS не выполнена' : 'DNS check not performed')}

---

## ⚡ ${language === 'ru' ? 'Анализ производительности' : 'Performance Analysis'}

${scan.performance ? `
| ${language === 'ru' ? 'Метрика' : 'Metric'} | ${language === 'ru' ? 'Значение' : 'Value'} | ${language === 'ru' ? 'Статус' : 'Status'} |
|--------|-------|--------|
| HTTP Status | ${scan.performance.statusCode} | ${scan.performance.statusCode === 200 ? 'OK' : 'WARNING'} |
| Response Time | ${scan.performance.responseTime}ms | ${scan.performance.responseTime < 500 ? 'OK' : scan.performance.responseTime < 1000 ? 'WARNING' : 'CRITICAL'} |
| TTFB | ${scan.performance.ttfb || 'N/A'}ms | ${scan.performance.ttfb && scan.performance.ttfb < 200 ? 'OK' : 'WARNING'} |
| HTTP Version | ${scan.performance.httpVersion || 'N/A'} | ${['HTTP/2', 'HTTP/3'].includes(scan.performance.httpVersion || '') ? 'OK' : 'WARNING'} |
| GZIP Compression | ${scan.performance.hasGzip ? '✅' : '❌'} | ${scan.performance.hasGzip ? 'OK' : 'WARNING'} |
| Brotli Compression | ${scan.performance.hasBrotli ? '✅' : '❌'} | ${scan.performance.hasBrotli ? 'OK' : 'INFO'} |
| Cache-Control | ${scan.performance.hasCacheControl ? '✅' : '❌'} | ${scan.performance.hasCacheControl ? 'OK' : 'WARNING'} |
| ETag | ${scan.performance.hasETag ? '✅' : '❌'} | ${scan.performance.hasETag ? 'OK' : 'WARNING'} |

**${language === 'ru' ? 'Рекомендации по производительности' : 'Performance Recommendations'}:**
${scan.performance.recommendations && Array.isArray(scan.performance.recommendations) && scan.performance.recommendations.length > 0 ? scan.performance.recommendations.map((rec: string) => `- ${rec}`).join('\n') : '✅ ' + (language === 'ru' ? 'Рекомендаций нет' : 'No recommendations')}
` : '❌ ' + (language === 'ru' ? 'Проверка производительности не выполнена' : 'Performance check not performed')}

---

## 🌐 ${language === 'ru' ? 'Анализ открытых портов' : 'Open Ports Analysis'}

${scan.portScans && scan.portScans.length > 0 ? `
| ${language === 'ru' ? 'Порт' : 'Port'} | ${language === 'ru' ? 'Протокол' : 'Protocol'} | ${language === 'ru' ? 'Сервис' : 'Service'} | ${language === 'ru' ? 'Состояние' : 'State'} | ${language === 'ru' ? 'Риск' : 'Risk'} |
|------|----------|---------|--------|------|
${scan.portScans.map((port: any) => `| ${port.port} | ${port.protocol} | ${port.service} | ${port.state} | ${port.risk} |`).join('\n')}
` : '❌ ' + (language === 'ru' ? 'Сканирование портов не выполнено' : 'Port scan not performed')}

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

## 🤖 AI Prompts for Fixing Issues (Enhanced with Context)

${(() => {
  const enricher = new SecurityReportEnricher(scan)
  const enrichedPrompts = enricher.generateEnrichedPrompts()

  return enrichedPrompts.length > 0 ? enrichedPrompts.map((prompt, i) => `
### ${prompt.id}: ${prompt.title}
**Type:** ${prompt.type || 'MISCELLANEOUS'} | **Severity:** ${prompt.severity} | **Action:** ${prompt.actionRequired}
**Likely Locations:** ${prompt.likelyLocations}

**Description:** ${prompt.description}

**Recommended Fix:** ${prompt.recommendedFix}

**Agent Context:** ${prompt.contextForAgent}

**Copy this prompt to Cursor/Cline:**

\`\`\`
${prompt.fullPrompt}
\`\`\`

**Expected Result:** ${prompt.recommendedFix}
`).join('\n') : '✅ No vulnerabilities found - no AI prompts needed'
})()}

---

## 📝 ${language === 'ru' ? 'Следующие шаги и рекомендации' : 'Next Steps & Recommendations'}

### ${language === 'ru' ? 'Немедленные действия (КРИТИЧЕСКИЕ)' : 'Immediate Actions (CRITICAL)'}:
${critical.length > 0 ? critical.map((v: any) => `- Fix: ${v.title}`).join('\n') : '- ' + (language === 'ru' ? 'Нет критических уязвимостей' : 'No critical vulnerabilities')}

### ${language === 'ru' ? 'Приоритетные действия (ВЫСОКИЕ)' : 'Priority Actions (HIGH)'}:
${high.length > 0 ? high.map((v: any) => `- Fix: ${v.title}`).join('\n') : '- ' + (language === 'ru' ? 'Нет уязвимостей высокой степени' : 'No high severity vulnerabilities')}

### ${language === 'ru' ? 'Планируемые действия (СРЕДНИЕ/НИЗКИЕ)' : 'Planned Actions (MEDIUM/LOW)'}:
${[...medium, ...low].length > 0 ? [...medium, ...low].map((v: any) => `- Fix: ${v.title}`).join('\n') : '- ' + (language === 'ru' ? 'Нет уязвимостей средней или низкой степени' : 'No medium or low severity vulnerabilities')}

### ${language === 'ru' ? 'Мониторинг' : 'Monitoring'}:
- ${language === 'ru' ? 'Регулярно сканировать сайт (ежемесячно)' : 'Regularly scan website (monthly)'}
- ${language === 'ru' ? 'Мониторить обновления зависимостей' : 'Monitor dependency updates'}
- ${language === 'ru' ? 'Подписаться на бюллетени безопасности' : 'Subscribe to security bulletins'}
- ${language === 'ru' ? 'Настроить автоматические уведомления' : 'Set up automated notifications'}

### ${language === 'ru' ? 'Обучение' : 'Training'}:
- ${language === 'ru' ? 'Изучить OWASP Top 10' : 'Study OWASP Top 10'}
- ${language === 'ru' ? 'Практиковаться на тестовых сайтах' : 'Practice on test websites'}
- ${language === 'ru' ? 'Читать блоги и исследования по безопасности' : 'Read security blogs and research'}

---

## 📞 ${language === 'ru' ? 'Поддержка и контакт' : 'Support & Contact'}

${language === 'ru' ? 'Если у вас есть вопросы по этому отчету или нужна помощь в исправлении уязвимостей:' : 'If you have questions about this report or need help fixing vulnerabilities:'}

- 📧 Email: security@example.com
- 💬 Discord: #security-help
- 📚 Wiki: https://wiki.example.com/security
- 🐛 Issues: https://github.com/example/security-audit/issues

---

*${language === 'ru' ? 'Отчет автоматически сгенерирован Security Audit Pro' : 'Report generated automatically by Security Audit Pro'}*
*${date}*
`

  return report
}

export async function POST(request: NextRequest) {
  console.log('=== API REPORT REQUEST ===')
  console.log('Report generation request received')

  try {
    const scanData = await request.json()
    const language: Language = scanData.language || 'en'
    console.log('📋 Received scan data for report generation')
    console.log('🌐 Language:', language)
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
    const markdown = generateMarkdownReport(scanData, language)
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
      name: error instanceof Error ? error.name : 'Unknown',
      message: error instanceof Error ? error.message : 'Unknown error',
      code: error instanceof Error && 'code' in error ? (error as any).code : undefined,
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

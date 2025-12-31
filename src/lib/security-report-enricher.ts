// Security Report Enrichment Engine
// Advanced AI Prompt Generator for IDE Agents (Cursor/Cline)

export interface Vulnerability {
  title: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  recommendation: string;
  owaspCategory?: string;
}

export interface EnrichedPrompt {
  id: string;
  title: string;
  type: string;
  severity: string;
  actionRequired: 'CODE_REFACTOR' | 'CONFIG_CHANGE' | 'EXTERNAL_ACTION';
  likelyLocations: string;
  description: string;
  recommendedFix: string;
  contextForAgent: string;
  fullPrompt: string;
}

export interface SecurityReport {
  vulnerabilities: Vulnerability[];
  url: string;
  domain: string;
  overallScore: number;
  riskLevel: string;
}

// SECURITY KNOWLEDGE BASE - Detailed Mapping Rules
const CONTEXT_MAP = {
  // SSL/TLS Category
  'SSL/TLS': {
    patterns: ['SSL', 'TLS', 'certificate', 'cipher', 'protocol', 'Mixed Content'],
    actionType: 'CONFIG_CHANGE' as const,
    mappings: {
      'Mixed Content': {
        locations: 'index.html, layout.tsx, src/app/layout.tsx',
        context: 'Search for http:// URLs in <img>, <script>, <link> tags. Replace with https:// or protocol-relative URLs (//). Check external CDN resources and API endpoints.'
      },
      'HTTP Available': {
        locations: 'vercel.json, next.config.js, nginx.conf',
        context: 'Implement 301 redirects from HTTP to HTTPS. In Vercel: add redirects in vercel.json. In Next.js: use next.config.js redirects array. In nginx: use return 301 directive.'
      },
      'Weak Ciphers': {
        locations: 'nginx.conf, apache2.conf, middleware.ts',
        context: 'Configure server to only accept strong ciphers (AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384). In Vercel Edge Middleware: check request headers and reject weak cipher suites.'
      },
      'Expired Certificate': {
        locations: 'SSL provider dashboard, vercel.json',
        context: 'Renew SSL certificate through hosting provider (Vercel automatically manages this). Check certificate validity dates and alert before expiration.'
      }
    }
  },

  // Security Headers Category (CRITICAL)
  'INSECURE_HEADERS': {
    patterns: ['Content-Security-Policy', 'HSTS', 'X-Frame-Options', 'X-Content-Type-Options', 'Permissions-Policy', 'Referrer-Policy'],
    actionType: 'CONFIG_CHANGE' as const,
    mappings: {
      'Content-Security-Policy': {
        locations: 'next.config.js, vercel.json, middleware.ts, src/app/layout.tsx',
        context: 'Add CSP header in next.config.js under headers array. Example: "Content-Security-Policy": "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'". Use nonce-based CSP for dynamic content.'
      },
      'X-Frame-Options': {
        locations: 'next.config.js, vercel.json, middleware.ts',
        context: 'Add "X-Frame-Options": "DENY" or "SAMEORIGIN" header. Prevents clickjacking attacks. Configure in next.config.js headers array or Vercel Edge Middleware.'
      },
      'X-Content-Type-Options': {
        locations: 'next.config.js, vercel.json, middleware.ts',
        context: 'Add "X-Content-Type-Options": "nosniff" header to prevent MIME type sniffing. Configure in next.config.js headers array.'
      },
      'Strict-Transport-Security': {
        locations: 'next.config.js, vercel.json, middleware.ts',
        context: 'Add HSTS header: "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload". Only enable after ensuring HTTPS works correctly.'
      },
      'Permissions-Policy': {
        locations: 'next.config.js, vercel.json, middleware.ts',
        context: 'Add "Permissions-Policy": "camera=(), microphone=(), geolocation=()" to restrict browser features. Configure in next.config.js headers array.'
      },
      'Referrer-Policy': {
        locations: 'next.config.js, vercel.json, middleware.ts',
        context: 'Add "Referrer-Policy": "strict-origin-when-cross-origin" to control referrer information leakage. Configure in next.config.js headers array.'
      }
    }
  },

  // DNS & Email Security Category
  'DNS': {
    patterns: ['SPF', 'DMARC', 'DKIM', 'DNSSEC'],
    actionType: 'EXTERNAL_ACTION' as const,
    mappings: {
      'Missing SPF': {
        locations: 'DNS provider (Cloudflare, GoDaddy, AWS Route53)',
        context: 'Add TXT record: "v=spf1 include:_spf.google.com ~all" or appropriate SPF record for your email provider. Test with tools like MX Toolbox.'
      },
      'Missing DMARC': {
        locations: 'DNS provider TXT records',
        context: 'Add TXT record: "_dmarc.domain.com IN TXT \\"v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com\\"". Start with p=quarantine, then move to p=reject.'
      },
      'Missing DKIM': {
        locations: 'Email provider DNS settings',
        context: 'Generate DKIM keys through email provider (Gmail, SendGrid, etc.) and add CNAME/TXT records as instructed. Usually involves adding multiple DNS records.'
      },
      'Missing DNSSEC': {
        locations: 'DNS provider advanced settings',
        context: 'Enable DNSSEC through DNS provider. Generate DS record and add to parent zone. Requires coordination between domain registrar and DNS host.'
      }
    }
  },

  // Performance Category
  'PERFORMANCE': {
    patterns: ['Gzip', 'Brotli', 'compression', 'caching', 'images', 'render blocking'],
    actionType: 'CONFIG_CHANGE' as const,
    mappings: {
      'Missing Gzip': {
        locations: 'vercel.json, next.config.js, nginx.conf',
        context: 'Enable compression in Vercel (automatic) or configure next.config.js: compress: true. For nginx: gzip on; gzip_types text/css application/javascript application/json.'
      },
      'Missing Brotli': {
        locations: 'vercel.json, nginx.conf',
        context: 'Vercel supports Brotli automatically. For nginx: brotli on; brotli_types text/css application/javascript. Modern browsers prefer Brotli over Gzip.'
      },
      'Missing Cache-Control': {
        locations: 'next.config.js, vercel.json, public/_headers',
        context: 'Add Cache-Control headers in next.config.js headers array. Example: "Cache-Control": "public, max-age=31536000, immutable" for static assets.'
      },
      'Render Blocking Resources': {
        locations: 'src/app/layout.tsx, next.config.js',
        context: 'Move CSS to <head>, use font-display: swap, defer non-critical JavaScript. Use Next.js <Script> component with strategy="afterInteractive".'
      }
    }
  },

  // XSS & Injection Vulnerabilities
  'XSS': {
    patterns: ['inline event handler', 'javascript:', 'innerHTML', 'dangerouslySetInnerHTML'],
    actionType: 'CODE_REFACTOR' as const,
    mappings: {
      'Inline Event Handlers': {
        locations: 'src/components/**/*.tsx, src/pages/**/*.tsx, public/index.html',
        context: 'Replace onclick="func()" with onClick={handleClick}. Replace javascript: URLs with proper event handlers. Use React synthetic events.'
      },
      'dangerouslySetInnerHTML': {
        locations: 'src/components/**/*.tsx, src/pages/**/*.tsx',
        context: 'Sanitize HTML content before using dangerouslySetInnerHTML. Use libraries like DOMPurify. Prefer React components over raw HTML insertion.'
      },
      'javascript: protocol': {
        locations: 'src/components/**/*.tsx, public/index.html',
        context: 'Remove javascript: URLs from href attributes. Implement proper event handlers using onClick or addEventListener. Use preventDefault() for custom behavior.'
      }
    }
  },

  // Information Disclosure
  'INFORMATION_DISCLOSURE': {
    patterns: ['Server header', 'technology disclosure', 'meta author', 'version disclosure'],
    actionType: 'CONFIG_CHANGE' as const,
    mappings: {
      'Server Technology Disclosure': {
        locations: 'vercel.json, next.config.js, middleware.ts',
        context: 'Remove or obscure server headers. In Next.js: poweredByHeader: false in next.config.js. In Vercel: use Edge Middleware to remove server headers.'
      },
      'Meta Author Tag': {
        locations: 'src/app/layout.tsx, public/index.html',
        context: 'Remove or anonymize <meta name="author"> tags that disclose developer information. Consider removing unnecessary meta tags.'
      },
      'Version Disclosure': {
        locations: 'package.json, next.config.js, public/index.html',
        context: 'Remove version numbers from public-facing content. Configure next.config.js to disable poweredByHeader. Avoid exposing framework versions.'
      }
    }
  },

  // Misc Configuration Issues
  'MISCONFIGURATION': {
    patterns: ['CORS', 'Open Graph', 'Robots.txt', 'WAF'],
    actionType: 'CONFIG_CHANGE' as const,
    mappings: {
      'Overly Permissive CORS': {
        locations: 'next.config.js, vercel.json, middleware.ts',
        context: 'Restrict CORS to specific origins. Replace "*" with actual domain list. Example: "Access-Control-Allow-Origin": "https://yourdomain.com".'
      },
      'Missing Open Graph': {
        locations: 'src/app/layout.tsx, public/index.html',
        context: 'Add Open Graph meta tags in layout.tsx. Include og:title, og:description, og:image, og:url for better social media sharing.'
      },
      'Missing Robots.txt': {
        locations: 'public/robots.txt',
        context: 'Create public/robots.txt file. Example: User-agent: *\\nAllow: /\\nDisallow: /admin/. Control search engine crawling behavior.'
      },
      'No WAF Detected': {
        locations: 'vercel.json, middleware.ts, external provider',
        context: 'Consider implementing Vercel Edge Middleware for basic WAF rules, or use external WAF like Cloudflare. Add rate limiting and basic security rules.'
      }
    }
  }
};

export class SecurityReportEnricher {
  private report: SecurityReport;

  constructor(report: SecurityReport) {
    this.report = report;
  }

  /**
   * Parse markdown report and extract vulnerabilities
   */
  static parseMarkdownReport(markdown: string): SecurityReport {
    // Extract basic info
    const urlMatch = markdown.match(/\*\*Target URL:\*\\*s*(.+)/);
    const domainMatch = markdown.match(/\*\*Domain:\*\*\\s*(.+)/);
    const scoreMatch = markdown.match(/\*\*Overall Score:\*\*\\s*(\\d+)/);

    // Extract vulnerabilities using regex
    const vulnBlocks = markdown.split(/(?=### \\d+\\.)/g);
    const vulnerabilities: Vulnerability[] = [];

    vulnBlocks.forEach(block => {
      const titleMatch = block.match(/### \\d+\\. (.+?)(?=\\n\\n|\\n\\*\\*Type:)/s);
      const typeMatch = block.match(/\\*\\*Type:\\*\\* (.+?)(?=\\n|$)/);
      const severityMatch = block.match(/\\*\\*Severity:\\*\\* (.+?)(?=\\n|$)/);
      const descMatch = block.match(/\\*\\*Description:\\*\\*\\n(.+?)(?=\\n\\n\\*\\*Recommendation:)/s);
      const recMatch = block.match(/\\*\\*Recommendation:\\*\\*\\n(.+?)(?=\\n\\n|$)/s);

      if (titleMatch && descMatch && recMatch) {
        vulnerabilities.push({
          title: titleMatch[1].trim(),
          type: typeMatch ? typeMatch[1].trim() : 'General',
          severity: (severityMatch ? severityMatch[1].trim() : 'MEDIUM') as any,
          description: descMatch[1].trim(),
          recommendation: recMatch[1].trim()
        });
      }
    });

    return {
      url: urlMatch ? urlMatch[1].trim() : '',
      domain: domainMatch ? domainMatch[1].trim() : '',
      overallScore: scoreMatch ? parseInt(scoreMatch[1]) : 0,
      riskLevel: 'UNKNOWN',
      vulnerabilities
    };
  }

  /**
   * Determine action type and context based on vulnerability type
   */
  private getContextForVulnerability(vuln: Vulnerability): {
    actionType: 'CODE_REFACTOR' | 'CONFIG_CHANGE' | 'EXTERNAL_ACTION';
    locations: string;
    context: string;
  } {
    // Find matching category
    for (const [category, config] of Object.entries(CONTEXT_MAP)) {
      if (config.patterns.some(pattern =>
        vuln.type.toLowerCase().includes(pattern.toLowerCase()) ||
        vuln.title.toLowerCase().includes(pattern.toLowerCase()) ||
        vuln.description.toLowerCase().includes(pattern.toLowerCase())
      )) {
        // Find specific mapping
        for (const [key, mapping] of Object.entries(config.mappings)) {
          if (vuln.title.toLowerCase().includes(key.toLowerCase()) ||
              vuln.description.toLowerCase().includes(key.toLowerCase())) {
            return {
              actionType: config.actionType,
              locations: mapping.locations,
              context: mapping.context
            };
          }
        }
        // Return category default if no specific mapping found
        return {
          actionType: config.actionType,
          locations: 'Check SECURITY KNOWLEDGE BASE for specific files',
          context: `Category: ${category}. Review the security knowledge base for specific implementation details.`
        };
      }
    }

    // Default fallback
    return {
      actionType: 'CONFIG_CHANGE',
      locations: 'next.config.js, vercel.json, src/app/layout.tsx',
      context: 'Review the vulnerability details and determine appropriate configuration changes. Check Next.js and Vercel documentation for implementation.'
    };
  }

  /**
   * Generate enriched AI prompt for a single vulnerability
   */
  private generateEnrichedPrompt(vuln: Vulnerability, index: number): EnrichedPrompt {
    const context = this.getContextForVulnerability(vuln);

    const fullPrompt = `Act as a Senior Security Engineer and an Expert Frontend/Backend Developer.

I have run a security audit and identified the following issue in the codebase:

**ISSUE TITLE:** ${vuln.title}
**SEVERITY:** ${vuln.severity}
**TYPE:** ${vuln.type}

**DESCRIPTION:**
${vuln.description}

**RECOMMENDATION:**
${vuln.recommendation}

**YOUR TASK:**
1. Analyze the relevant files in the current workspace to locate where this issue exists.
2. Implement the necessary code or configuration changes to fix this vulnerability according to the recommendation.
3. Ensure the fix follows best security practices (OWASP).
4. Explain briefly what you changed and why.

**SPECIFIC CONTEXT:**
${context.context}

**LIKELY FILE LOCATIONS:**
${context.locations}

**ACTION TYPE REQUIRED:**
${context.actionType}

**Constraints:**
- Do not ask me for permission, just fix it.
- If the issue is in a config file (like vercel.json, next.config.js, headers), modify it directly.
- Be precise and provide working code examples.
- Test the changes to ensure they work correctly.

**URL:** ${this.report.url}
**DOMAIN:** ${this.report.domain}`;

    return {
      id: `task-${index + 1}`,
      title: vuln.title,
      type: vuln.type,
      severity: vuln.severity,
      actionRequired: context.actionType,
      likelyLocations: context.locations,
      description: vuln.description,
      recommendedFix: vuln.recommendation,
      contextForAgent: context.context,
      fullPrompt
    };
  }

  /**
   * Generate enriched prompts for all vulnerabilities
   */
  generateEnrichedPrompts(): EnrichedPrompt[] {
    return this.report.vulnerabilities.map((vuln, index) =>
      this.generateEnrichedPrompt(vuln, index)
    );
  }

  /**
   * Generate remediation plan summary
   */
  generateRemediationPlan(): {
    summary: string;
    enrichedPrompts: EnrichedPrompt[];
    actionBreakdown: {
      CODE_REFACTOR: number;
      CONFIG_CHANGE: number;
      EXTERNAL_ACTION: number;
    };
  } {
    const enrichedPrompts = this.generateEnrichedPrompts();

    const actionBreakdown = {
      CODE_REFACTOR: enrichedPrompts.filter(p => p.actionRequired === 'CODE_REFACTOR').length,
      CONFIG_CHANGE: enrichedPrompts.filter(p => p.actionRequired === 'CONFIG_CHANGE').length,
      EXTERNAL_ACTION: enrichedPrompts.filter(p => p.actionRequired === 'EXTERNAL_ACTION').length,
    };

    const summary = `# 🔧 Security Remediation Plan

**Target:** ${this.report.url}
**Domain:** ${this.report.domain}
**Current Score:** ${this.report.overallScore}/100
**Risk Level:** ${this.report.riskLevel}

## 📊 Action Breakdown
- **Code Refactoring:** ${actionBreakdown.CODE_REFACTOR} issues
- **Configuration Changes:** ${actionBreakdown.CONFIG_CHANGE} issues
- **External Actions:** ${actionBreakdown.EXTERNAL_ACTION} issues

## 🎯 Priority Order
1. **Immediate (CRITICAL):** Fix all CRITICAL severity issues
2. **High Priority:** Address CONFIG_CHANGE items (headers, SSL, DNS)
3. **Medium Priority:** Handle CODE_REFACTOR items (XSS, injections)
4. **Low Priority:** External actions (manual DNS, WAF setup)

## 📋 Detailed Tasks
${enrichedPrompts.map(prompt => `
### ${prompt.id}: ${prompt.title}
**Type:** ${prompt.type} | **Severity:** ${prompt.severity} | **Action:** ${prompt.actionRequired}
**Locations:** ${prompt.likelyLocations}

**Description:** ${prompt.description}

**Fix:** ${prompt.recommendedFix}

**Agent Context:** ${prompt.contextForAgent}
`).join('\n')}

## 🚀 Implementation Notes
- Start with CONFIG_CHANGE items (headers, SSL) - these give immediate security improvements
- Address CODE_REFACTOR items systematically across components
- Schedule EXTERNAL_ACTION items for separate implementation
- Test all changes in staging environment before production deployment
- Re-run security scan after fixes to verify improvements

---
*Generated by Security Report Enrichment Engine*
*${new Date().toISOString()}*`;

    return {
      summary,
      enrichedPrompts,
      actionBreakdown
    };
  }
}

// Utility functions for integration
export function enrichSecurityReport(markdownReport: string): {
  summary: string;
  enrichedPrompts: EnrichedPrompt[];
  actionBreakdown: any;
} {
  const parsedReport = SecurityReportEnricher.parseMarkdownReport(markdownReport);
  const enricher = new SecurityReportEnricher(parsedReport);
  return enricher.generateRemediationPlan();
}

export function generateAIPromptsForReport(markdownReport: string): EnrichedPrompt[] {
  const parsedReport = SecurityReportEnricher.parseMarkdownReport(markdownReport);
  const enricher = new SecurityReportEnricher(parsedReport);
  return enricher.generateEnrichedPrompts();
}
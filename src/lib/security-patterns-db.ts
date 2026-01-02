/**
 * SECURITY_PATTERNS_DB.ts
 * Embedded Security Patterns Database
 * Covers CSP, Cookie Security, SPA/Modern App, OWASP Top 10
 */

// ===========================
// 1. CSP (Content Security Policy) PATTERNS
// ===========================
export const CSP_PATTERNS_DB: Record<string, {
  severity: string;
  owasp: string;
  title: string;
  description: string;
  recommendation: string;
  category?: string;
}> = {
  // Dangerous directives
  'unsafe-inline': {
    severity: 'HIGH',
    owasp: 'A03',
    title: 'CSP Allows unsafe-inline',
    description: 'Content Security Policy allows inline scripts with \'unsafe-inline\', which can be exploited for XSS attacks.',
    recommendation: 'Remove \'unsafe-inline\' from script-src directive. Use nonce-based CSP: script-src \'self\' \'nonce-xyz\'',
    category: 'INSECURE_HEADERS',
  },
  'unsafe-eval': {
    severity: 'HIGH',
    owasp: 'A03',
    title: 'CSP Allows unsafe-eval',
    description: 'Content Security Policy allows eval() and similar functions with \'unsafe-eval\', which can be exploited.',
    recommendation: 'Remove \'unsafe-eval\' from script-src directive. Avoid using eval() in your code.',
    category: 'INSECURE_HEADERS',
  },
  'data-url': {
    severity: 'MEDIUM',
    owasp: 'A03',
    title: 'CSP Allows data: URLs',
    description: 'Content Security Policy allows data: URLs, which can be exploited for XSS attacks via data URIs.',
    recommendation: 'Restrict data: URLs to specific cases (e.g., data: image/png) or remove if not needed.',
    category: 'INSECURE_HEADERS',
  },
  'wildcard-origin': {
    severity: 'MEDIUM',
    owasp: 'A03',
    title: 'CSP Allows Wildcard Origins',
    description: 'Content Security Policy allows wildcard (*) or broad patterns, which defeats the purpose of CSP.',
    recommendation: 'Replace wildcards with specific trusted domains in CSP directives.',
    category: 'INSECURE_HEADERS',
  },
  'missing-default-src': {
    severity: 'MEDIUM',
    owasp: 'A03',
    title: 'Missing default-src Directive',
    description: 'Content Security Policy is missing a default-src directive, leaving some resources unprotected.',
    recommendation: 'Add default-src directive: default-src \'self\'',
    category: 'INSECURE_HEADERS',
  },
  'missing-script-src': {
    severity: 'MEDIUM',
    owasp: 'A03',
    title: 'Missing script-src Directive',
    description: 'Content Security Policy is missing a script-src directive, which is critical for XSS prevention.',
    recommendation: 'Add script-src directive: script-src \'self\'',
    category: 'INSECURE_HEADERS',
  },
  'missing-style-src': {
    severity: 'LOW',
    owasp: 'A03',
    title: 'Missing style-src Directive',
    description: 'Content Security Policy is missing a style-src directive.',
    recommendation: 'Add style-src directive: style-src \'self\'',
    category: 'INSECURE_HEADERS',
  },
  'missing-img-src': {
    severity: 'LOW',
    owasp: 'A03',
    title: 'Missing img-src Directive',
    description: 'Content Security Policy is missing a img-src directive.',
    recommendation: 'Add img-src directive: img-src \'self\' https:',
    category: 'INSECURE_HEADERS',
  },
  'report-only-mode': {
    severity: 'INFO',
    owasp: 'A03',
    title: 'CSP in Report-Only Mode',
    description: 'Content Security Policy is in report-only mode. CSP violations are not enforced.',
    recommendation: 'Remove Content-Security-Policy-Report-Only header and use Content-Security-Policy for enforcement.',
    category: 'INSECURE_HEADERS',
  },
};

// ===========================
// 2. COOKIE SECURITY PATTERNS
// ===========================
export const COOKIE_PATTERNS_DB: Record<string, {
  severity: string;
  owasp: string;
  title: string;
  description: string;
  recommendation: string;
  category: string;
}> = {
  'missing-secure': {
    severity: 'MEDIUM',
    owasp: 'A07',
    title: 'Cookie Missing Secure Flag',
    description: 'Cookie is transmitted over unencrypted HTTP connections, making it vulnerable to interception.',
    recommendation: 'Add "Secure" flag to cookie to only transmit over HTTPS.',
    category: 'INSECURE_COOKIES',
  },
  'missing-httponly': {
    severity: 'HIGH',
    owasp: 'A07',
    title: 'Cookie Missing HttpOnly Flag',
    description: 'Cookie is accessible via JavaScript, making it vulnerable to XSS attacks.',
    recommendation: 'Add "HttpOnly" flag to prevent client-side scripts from accessing cookie.',
    category: 'INSECURE_COOKIES',
  },
  'missing-samesite': {
    severity: 'MEDIUM',
    owasp: 'A07',
    title: 'Cookie Missing SameSite Flag',
    description: 'Cookie is sent with all cross-site requests, increasing CSRF attack risk.',
    recommendation: 'Add "SameSite=Strict" or "SameSite=Lax" attribute to prevent CSRF attacks.',
    category: 'INSECURE_COOKIES',
  },
  'weak-samesite-none': {
    severity: 'MEDIUM',
    owasp: 'A07',
    title: 'Cookie SameSite Set to None',
    description: 'Cookie with SameSite=None can be sent with cross-site requests without user interaction.',
    recommendation: 'Use SameSite=Lax or SameSite=Strict for better CSRF protection.',
    category: 'INSECURE_COOKIES',
  },
  'long-expiration': {
    severity: 'LOW',
    owasp: 'A07',
    title: 'Cookie Long Expiration Time',
    description: 'Cookie has a very long expiration time, increasing exposure if compromised.',
    recommendation: 'Reduce cookie expiration time to a reasonable duration (e.g., 1-7 days).',
    category: 'INSECURE_COOKIES',
  },
  'no-expiration': {
    severity: 'MEDIUM',
    owasp: 'A07',
    title: 'Cookie Without Expiration',
    description: 'Cookie has no expiration time, will persist until browser is closed.',
    recommendation: 'Add Expires or Max-Age attribute with reasonable duration.',
    category: 'INSECURE_COOKIES',
  },
};

// ===========================
// 3. SPA / MODERN APP PATTERNS
// ===========================
export const SPA_PATTERNS_DB: Record<string, {
  severity: string;
  owasp?: string;
  title: string;
  description: string;
  recommendation: string;
  category: string;
}> = {
  // Source map exposure
  'source-map-reference': {
    severity: 'MEDIUM',
    title: 'Source Map Exposed',
    description: 'JavaScript source maps are accessible, which can expose source code structure.',
    recommendation: 'Remove sourceMappingURL from production builds or block access to .map files.',
    category: 'INFORMATION_DISCLOSURE',
  },
  'webpack-devtools-exposed': {
    severity: 'HIGH',
    title: 'Webpack DevTools Exposed',
    description: 'Webpack DevTools overlay is available in production, exposing build details.',
    recommendation: 'Remove or disable Webpack DevTools in production builds.',
    category: 'INFORMATION_DISCLOSURE',
  },
  // Next.js specific
  'nextjs-build-id-leak': {
    severity: 'HIGH',
    title: 'Next.js Build ID Leaked',
    description: 'Next.js build ID is exposed in client-side code, potentially leaking server info.',
    recommendation: 'Ensure build IDs are not exposed in client bundles.',
    category: 'INFORMATION_DISCLOSURE',
  },
  'nextjs-data-href': {
    severity: 'INFO',
    title: 'Next.js data-href in Production',
    description: 'Next.js data-href attributes detected, which may indicate development build artifacts.',
    recommendation: 'Remove data-href attributes from production builds.',
    category: 'MISCONFIGURATION',
  },
  'nextjs-debug-mode': {
    severity: 'CRITICAL',
    title: 'Next.js Debug Mode Enabled',
    description: 'Next.js debug mode is enabled in production, exposing sensitive information.',
    recommendation: 'Disable debug mode in production environment.',
    category: 'CRITICAL_MISCONFIGURATION',
  },
  // React patterns
  'dangerously-set-innerhtml': {
    severity: 'MEDIUM',
    owasp: 'A03',
    title: 'React dangerouslySetInnerHTML Usage',
    description: 'React dangerouslySetInnerHTML is used without proper sanitization.',
    recommendation: 'Use React components and avoid dangerouslySetInnerHTML, or properly sanitize input.',
    category: 'INSECURE_REACT',
  },
  'missing-csrf-token': {
    severity: 'MEDIUM',
    owasp: 'A01',
    title: 'Forms Without CSRF Token',
    description: 'Forms are missing CSRF tokens, vulnerable to cross-site request forgery.',
    recommendation: 'Implement CSRF tokens in forms using synchronizer token pattern.',
    category: 'INSECURE_AUTH',
  },
  // Module patterns
  'exposed-module-bundle': {
    severity: 'MEDIUM',
    title: 'Exposed Module Bundle',
    description: 'Unminified or exposed module bundles detected, revealing code structure.',
    recommendation: 'Minify and obfuscate production bundles.',
    category: 'INFORMATION_DISCLOSURE',
  },
  'webpack-runtime-exposed': {
    severity: 'LOW',
    title: 'Webpack Runtime Exposed',
    description: 'Webpack runtime files are accessible, revealing build configuration.',
    recommendation: 'Obfuscate webpack runtime in production builds.',
    category: 'INFORMATION_DISCLOSURE',
  },
  // Common SPA issues
  'hardcoded-api-keys': {
    severity: 'CRITICAL',
    title: 'Hardcoded API Keys',
    description: 'API keys or secrets detected in client-side JavaScript.',
    recommendation: 'Move API keys to server-side or environment variables.',
    category: 'INFORMATION_DISCLOSURE',
  },
  'client-side-secrets': {
    severity: 'HIGH',
    title: 'Client-Side Secrets',
    description: 'Secrets or sensitive configuration detected in client code.',
    recommendation: 'Never include secrets in client-side code. Use environment variables on server.',
    category: 'INFORMATION_DISCLOSURE',
  },
};

// ===========================
// 4. OWASP TOP 10 STATIC PATTERNS
// ===========================
export const OWASP_PATTERNS_DB: Record<string, {
  severity: string;
  owasp: string;
  title: string;
  description: string;
  recommendation: string;
  category: string;
}> = {
  // A01: Broken Access Control
  'missing-csp': {
    severity: 'HIGH',
    owasp: 'A01',
    title: 'Missing Content Security Policy',
    description: 'Content Security Policy (CSP) header is not set, leaving application vulnerable to XSS attacks.',
    recommendation: 'Implement Content-Security-Policy header with appropriate directives.',
    category: 'BROKEN_ACCESS_CONTROL',
  },
  'missing-hsts': {
    severity: 'HIGH',
    owasp: 'A01',
    title: 'Missing HSTS Header',
    description: 'HTTP Strict Transport Security (HSTS) header is not set, allowing downgrade to HTTP.',
    recommendation: 'Add Strict-Transport-Security header with max-age >= 31536000.',
    category: 'BROKEN_ACCESS_CONTROL',
  },
  'missing-x-frame-options': {
    severity: 'MEDIUM',
    owasp: 'A01',
    title: 'Missing X-Frame-Options Header',
    description: 'X-Frame-Options header is not set, allowing clickjacking attacks.',
    recommendation: 'Add X-Frame-Options header with DENY or SAMEORIGIN.',
    category: 'BROKEN_ACCESS_CONTROL',
  },
  'missing-x-content-type-options': {
    severity: 'MEDIUM',
    owasp: 'A01',
    title: 'Missing X-Content-Type-Options Header',
    description: 'X-Content-Type-Options header is not set, allowing MIME sniffing.',
    recommendation: 'Add X-Content-Type-Options: nosniff header.',
    category: 'BROKEN_ACCESS_CONTROL',
  },

  // A02: Cryptographic Failures
  'weak-tls': {
    severity: 'CRITICAL',
    owasp: 'A02',
    title: 'Weak TLS Configuration',
    description: 'Website is using outdated or weak TLS protocol (SSLv3, TLS 1.0, or TLS 1.1).',
    recommendation: 'Upgrade to TLS 1.2 or 1.3 and use strong cipher suites.',
    category: 'CRYPTOGRAPHIC_FAILURE',
  },
  'missing-ssl': {
    severity: 'HIGH',
    owasp: 'A02',
    title: 'Missing SSL/TLS Certificate',
    description: 'Website is not using HTTPS, transmitting data in plain text.',
    recommendation: 'Implement SSL/TLS certificate and redirect HTTP to HTTPS.',
    category: 'CRYPTOGRAPHIC_FAILURE',
  },
  'expired-ssl': {
    severity: 'HIGH',
    owasp: 'A02',
    title: 'Expired SSL/TLS Certificate',
    description: 'SSL/TLS certificate has expired, causing security warnings and man-in-the-middle risks.',
    recommendation: 'Renew SSL/TLS certificate before expiration.',
    category: 'CRYPTOGRAPHIC_FAILURE',
  },
  'http-on-https': {
    severity: 'HIGH',
    owasp: 'A02',
    title: 'Insecure Form Action on HTTPS Page',
    description: 'Form on HTTPS page submits to HTTP endpoint, sending data unencrypted.',
    recommendation: 'Update all form actions to use HTTPS to protect sensitive data.',
    category: 'CRYPTOGRAPHIC_FAILURE',
  },

  // A03: Injection
  'eval-pattern': {
    severity: 'CRITICAL',
    owasp: 'A03',
    title: 'Eval() Pattern Detected',
    description: 'Code contains eval() or similar dynamic code execution, which can be exploited for injection attacks.',
    recommendation: 'Remove eval() usage. Use safer alternatives like JSON.parse() or component rendering.',
    category: 'CODE_INJECTION',
  },
  'javascript-href': {
    severity: 'HIGH',
    owasp: 'A03',
    title: 'javascript: Protocol in href',
    description: 'Anchor tags use javascript: protocol, which can execute arbitrary JavaScript.',
    recommendation: 'Remove javascript: protocol from href attributes. Use event listeners instead.',
    category: 'XSS',
  },
  'inline-event-handlers': {
    severity: 'MEDIUM',
    owasp: 'A03',
    title: 'Inline Event Handlers',
    description: 'HTML contains inline event handlers (onclick, onerror, etc.), which can be XSS vectors.',
    recommendation: 'Remove inline event handlers and use addEventListener in JavaScript.',
    category: 'XSS',
  },

  // A05: Security Misconfiguration
  'server-header-disclosure': {
    severity: 'LOW',
    owasp: 'A05',
    title: 'Server Technology Disclosure',
    description: 'Server header reveals server technology and version.',
    recommendation: 'Configure server to hide or minimize server information in headers.',
    category: 'INFORMATION_DISCLOSURE',
  },
  'directory-listing': {
    severity: 'MEDIUM',
    owasp: 'A05',
    title: 'Directory Listing Enabled',
    description: 'Web server allows directory listing, exposing file structure.',
    recommendation: 'Disable directory listing in web server configuration.',
    category: 'SECURITY_MISCONFIGURATION',
  },
  'sensitive-files-exposed': {
    severity: 'HIGH',
    owasp: 'A05',
    title: 'Sensitive Files Exposed',
    description: 'Sensitive files (.env, .git, logs) are accessible via web.',
    recommendation: 'Move sensitive files outside web root or block access via server config.',
    category: 'SECURITY_MISCONFIGURATION',
  },
  'debug-endpoints': {
    severity: 'HIGH',
    owasp: 'A05',
    title: 'Debug Endpoints Accessible',
    description: 'Debug or test endpoints are accessible in production.',
    recommendation: 'Remove or protect debug endpoints from public access.',
    category: 'SECURITY_MISCONFIGURATION',
  },

  // A07: Auth Failures
  'missing-csrf-token': {
    severity: 'MEDIUM',
    owasp: 'A07',
    title: 'Forms Without CSRF Token',
    description: 'Forms are missing CSRF tokens, vulnerable to cross-site request forgery.',
    recommendation: 'Implement CSRF tokens in forms using synchronizer token pattern.',
    category: 'INSECURE_AUTH',
  },
  'weak-password-policy': {
    severity: 'MEDIUM',
    owasp: 'A07',
    title: 'Weak Password Policy',
    description: 'No evidence of strong password requirements or password strength validation.',
    recommendation: 'Implement strong password policy (min 8 chars, mixed case, numbers, symbols).',
    category: 'INSECURE_AUTH',
  },
  'missing-rate-limiting': {
    severity: 'MEDIUM',
    owasp: 'A07',
    title: 'Missing Rate Limiting',
    description: 'No evidence of rate limiting on authentication endpoints.',
    recommendation: 'Implement rate limiting on login and authentication endpoints.',
    category: 'INSECURE_AUTH',
  },

  // A08: Software Integrity
  'missing-sri': {
    severity: 'MEDIUM',
    owasp: 'A08',
    title: 'Missing Subresource Integrity (SRI)',
    description: 'External resources are loaded without Subresource Integrity (SRI) hashes.',
    recommendation: 'Add integrity attribute with SHA-256/384/512 hash to prevent CDN compromise.',
    category: 'SOFTWARE_INTEGRITY',
  },
  'missing-subresource-integrity': {
    severity: 'MEDIUM',
    owasp: 'A08',
    title: 'Missing Subresource Integrity',
    description: 'External scripts/styles loaded without integrity verification.',
    recommendation: 'Implement Subresource Integrity (SRI) for all external resources.',
    category: 'SOFTWARE_INTEGRITY',
  },

  // A09: Logging
  'missing-csp-report-uri': {
    severity: 'INFO',
    owasp: 'A09',
    title: 'Missing CSP Report URI',
    description: 'CSP does not specify a report-uri for violation monitoring.',
    recommendation: 'Add report-uri directive to Content-Security-Policy for CSP violation logging.',
    category: 'LOGGING_MONITORING',
  },
  'logging-sensitive-data': {
    severity: 'MEDIUM',
    owasp: 'A09',
    title: 'Sensitive Data in Logs',
    description: 'Log files may contain sensitive information exposed via web.',
    recommendation: 'Move log files outside web root and implement log rotation.',
    category: 'LOGGING_MONITORING',
  },

  // A10: SSRF
  'fetch-to-unknown-host': {
    severity: 'HIGH',
    owasp: 'A10',
    title: 'Potential SSRF via Fetch',
    description: 'Code contains fetch() calls to user-controlled URLs, potential SSRF vector.',
    recommendation: 'Validate and whitelist allowed hosts for fetch requests.',
    category: 'SSRF',
  },
  'user-controlled-url': {
    severity: 'MEDIUM',
    owasp: 'A10',
    title: 'User-Controlled URLs',
    description: 'Application makes requests to URLs controlled by user input.',
    recommendation: 'Implement URL validation and allowlist for external requests.',
    category: 'SSRF',
  },
};

// ===========================
// 5. HELPER FUNCTIONS
// ===========================

/**
 * Check CSP policy for dangerous patterns
 */
export function analyzeCSPPolicy(cspValue: string | null | undefined) {
  if (!cspValue) {
    return [
      {
        ...CSP_PATTERNS_DB['missing-default-src'],
        evidence: { csp: null },
      }
    ];
  }

  const issues: any[] = [];
  const directives = cspValue.split(';').map((d: string) => d.trim().toLowerCase());

  // Check for dangerous patterns
  const cspString = cspValue.toLowerCase();

  if (cspString.includes("'unsafe-inline'")) {
    issues.push({
      ...CSP_PATTERNS_DB['unsafe-inline'],
      evidence: { directive: 'script-src' }
    });
  }

  if (cspString.includes("'unsafe-eval'")) {
    issues.push({
      ...CSP_PATTERNS_DB['unsafe-eval'],
      evidence: { directive: 'script-src' }
    });
  }

  if (cspString.includes('data:')) {
    issues.push({
      ...CSP_PATTERNS_DB['data-url'],
      evidence: { directive: 'script-src' }
    });
  }

  if (cspString.includes('*') && cspString.includes('script-src')) {
    // Check if wildcard is in script-src or default-src
    const scriptSrcIndex = directives.findIndex((d: string) => d.startsWith('script-src'));
    if (scriptSrcIndex >= 0) {
      if (directives[scriptSrcIndex].includes('*')) {
        issues.push({
          ...CSP_PATTERNS_DB['wildcard-origin'],
          evidence: { directive: 'script-src' }
        });
      }
    }
  }

  // Check for missing directives
  if (!cspString.includes('default-src')) {
    issues.push({
      ...CSP_PATTERNS_DB['missing-default-src'],
      evidence: {}
    });
  }

  if (!cspString.includes('script-src')) {
    issues.push({
      ...CSP_PATTERNS_DB['missing-script-src'],
      evidence: {}
    });
  }

  if (!cspString.includes('style-src')) {
    issues.push({
      ...CSP_PATTERNS_DB['missing-style-src'],
      evidence: {}
    });
  }

  if (!cspString.includes('img-src')) {
    issues.push({
      ...CSP_PATTERNS_DB['missing-img-src'],
      evidence: {}
    });
  }

  return issues;
}

/**
 * Analyze cookie security
 */
export function analyzeCookieSecurity(setCookieHeaders: string[]) {
  const issues: any[] = [];

  setCookieHeaders.forEach((cookie: string) => {
    if (!cookie.includes('Secure')) {
      issues.push({
        ...COOKIE_PATTERNS_DB['missing-secure'],
        evidence: { cookie: cookie.split(';')[0] }
      });
    }

    if (!cookie.includes('HttpOnly')) {
      issues.push({
        ...COOKIE_PATTERNS_DB['missing-httponly'],
        evidence: { cookie: cookie.split(';')[0] }
      });
    }

    if (!cookie.includes('SameSite')) {
      issues.push({
        ...COOKIE_PATTERNS_DB['missing-samesite'],
        evidence: { cookie: cookie.split(';')[0] }
      });
    } else if (cookie.includes('SameSite=None')) {
      issues.push({
        ...COOKIE_PATTERNS_DB['weak-samesite-none'],
        evidence: { cookie: cookie.split(';')[0] }
      });
    }

    // Check for long expiration
    const maxAgeMatch = cookie.match(/max-age=(\d+)/i);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1]);
      // More than 30 days
      if (maxAge > 2592000) {
        issues.push({
          ...COOKIE_PATTERNS_DB['long-expiration'],
          evidence: { maxAge, days: Math.round(maxAge / 86400) }
        });
      }
    }
  });

  return issues;
}

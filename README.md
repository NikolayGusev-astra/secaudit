# 🛡️ Security Audit Tool - SecAudit Pro

**Professional web application security scanner with OWASP Top 10 compliance checking**

[![Security Audit Badge](https://img.shields.io/badge/Security%20Audit-green.svg)](https://img.shields.io/badge/Security%20Audit-green.svg)

---

## ✨ Features

- 🔍 **Real-time Security Scanning** - Comprehensive security analysis in seconds
- 📊 **Detailed Scoring** - Security scores (0-100) by category with risk levels
- 🛡️ **Vulnerability Detection** - OWASP Top 10, XSS, SQL Injection, CSRF protection
- 🔒 **SSL/TLS Analysis** - Certificate validation, expiration tracking, cipher strength
- 📋 **DNS Security** - SPF, DMARC, DKIM, DNSSEC detection
- 🎯 **Security Headers** - CSP, HSTS, X-Frame-Options, X-Content-Type-Options analysis
- ⚡ **Performance Metrics** - Response time, TTFB, compression detection
- 🌐 **Port Scanning** - Open port detection and risk assessment
- 🍪 **Cookie Security** - Secure, HttpOnly, SameSite attribute analysis
- 📤 **CORS Policy** - Cross-Origin Resource Sharing validation
- 📝 **WAF Detection** - Web Application Firewall identification
- 📄 **Content Injection Checks** - Inline event handlers, dangerouslySetInnerHTML detection
- 🎨 **Open Graph Analysis** - OG tags, Twitter Cards validation
- 📚 **Sensitive Files Detection** - Smart content validation to avoid false positives

---

## 🚀 Technology Stack

- **Frontend:** Next.js 15 + TypeScript + React 19 + Tailwind CSS 4 + shadcn/ui
- **Backend:** Next.js API Routes with real-time DNS checks
- **Scanning:** Hybrid vulnerability checking with offline mode support
- **Icons:** Lucide React
- **Charts:** Recharts

---

## 🎯 Project Status

**Version:** 1.0.0  
**Last Updated:** January 3, 2026  
**License:** MIT  
**Status:** Production Ready ✅

---

## 📦 Quick Start

### Prerequisites

```bash
# Clone the repository
git clone https://github.com/NikolayGusev-astra/secaudit.git

# Navigate to project directory
cd secaudit

# Install dependencies
npm install
# or
bun install
```

### Environment Setup

```bash
# Copy environment variables
cp .env.example .env.local

# Edit .env.local with your settings
nano .env.local
```

### Development

```bash
# Start development server
npm run dev

# or
bun run dev
# or
node next dev
```

### Build for Production

```bash
# Create production build
npm run build

# or
bun run build
```

### Deployment to Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Login to Vercel
vercel login

# Deploy project
vercel
```

---

## 📂 Architecture

### Directory Structure

```
secaudit/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   └── security/
│   │   │       ├── scan/route.ts       # Security scan API
│   │   │       └── report/route.ts       # Report generation API
│   │   ├── page.tsx                      # Main page with security scanner
│   │   ├── layout.tsx                    # Root layout with metadata
│   │   └── globals.css                    # Global styles
│   ├── components/
│   │   └── ui/                      # shadcn/ui components
│   ├── lib/
│   │   ├── dnssec-checker.ts          # DNS security checking
│   │   ├── hybrid-vulnerability-checker.ts  # Hybrid vulnerability detection
│   │   ├── security-patterns-db.ts      # OWASP security patterns
│   │   ├── security-report-enricher.ts  # Report enrichment
│   │   └── vulnerability-db.js        # Vulnerability database
│   └── hooks/                         # Custom React hooks
├── next.config.ts                   # Next.js configuration
├── package.json                     # Dependencies
├── tailwind.config.ts                # Tailwind CSS configuration
├── tsconfig.json                    # TypeScript configuration
└── public/                           # Static assets
```

---

## 🔒 Security Checks Overview

### 1. SSL/TLS Certificate Checker
- Certificate validation
- Issuer detection
- Expiration tracking
- TLS version detection
- Cipher strength analysis
- Self-signed certificate detection

### 2. Security Headers Analyzer
- Content-Security-Policy (CSP) analysis
- Strict-Transport-Security (HSTS) validation
- X-Frame-Options checking
- X-Content-Type-Options validation
- X-XSS-Protection detection
- Referrer-Policy analysis
- Permissions-Policy validation

### 3. DNS Security Checker
- A/AAAA record validation
- NS record detection
- MX record analysis
- TXT record scanning (SPF, DMARC, DKIM)
- DNSSEC validation
- **Smart Email Detection:**
  - Detects email functionality (forms, newsletter, signup)
  - Adjusts scoring: websites without email get bonus score
  - Prevents false penalties for non-email sites

### 4. Performance Checker
- Response time measurement
- TTFB (Time To First Byte) calculation
- HTTP/3 detection
- GZIP compression detection
- Brotli compression detection
- Cache-Control header validation
- ETag header validation

### 5. Vulnerability Scanner
- OWASP Top 10 compliance checking
- XSS (Cross-Site Scripting) detection
- SQL Injection detection
- CSRF (Cross-Site Request Forgery) protection
- Information disclosure detection
- Mixed content analysis
- Insecure form action detection
- Cookie security analysis
- Sensitive files exposure detection (with smart validation)

### 6. Cookie Security Analyzer
- Secure flag validation
- HttpOnly flag validation
- SameSite attribute analysis
- Expiration time analysis

### 7. CORS Policy Analyzer
- Wildcard origin detection
- Credentials with wildcard validation
- Overly permissive CORS detection
- Missing CORS headers detection

### 8. WAF Detector
- Cloudflare WAF detection
- Akamai WAF detection
- Fastly WAF detection
- Imperva Incapsula detection
- Sucuri WAF detection
- Azure WAF detection
- AWS WAF detection
- ModSecurity detection
- Barracuda WAF detection

### 9. SRI (Subresource Integrity) Checker
- External resource hash validation
- CDN compromise prevention
- SHA-256/384/512 hash generation

### 10. Content Injection Checker
- Template pattern detection (EJS, ERB, etc.)
- Eval() usage detection
- Inline event handler detection
- JavaScript: protocol detection
- dangerouslySetInnerHTML detection (React pattern)

### 11. Open Graph & Social Media Analyzer
- OG:title validation
- OG:description validation
- OG:image validation
- OG:url validation
- OG:type validation
- twitter:card validation
- Meta author tag detection
- Meta generator tag detection

### 12. Port Scanner
- HTTP/HTTPS/SSH/FTP port scanning
- Risk level assessment (LOW/MEDIUM/HIGH/INFO)
- Service detection

---

## 🎨 User Interface

### Components
- Modern, responsive design using shadcn/ui
- Dark mode support
- Real-time scan results display
- Tab-based navigation for different security categories
- Export functionality (Markdown, JSON, CSV)
- Interactive vulnerability details with severity badges
- Performance metrics visualization

### Pages
- `/` - Main security scanner page
- `/report` - Detailed vulnerability report with AI prompts

---

## 🛡️ Security Categories

### SSL/TLS (100 points max)
- Certificate present: +30 points
- Valid certificate: +15 points
- Strong TLS version: +5 points

### Security Headers (100 points max)
- CSP header: +14 points
- HSTS header: +14 points
- X-Frame-Options: +14 points
- X-Content-Type-Options: +14 points
- X-XSS-Protection: +14 points
- Referrer-Policy: +14 points
- Permissions-Policy: +14 points

### DNS Security (100 points max)
- A record: +20 points
- NS record: +10 points
- MX record: +15 points
- SPF record: +20 points (if MX exists)
- DMARC record: +20 points (if MX exists)
- DKIM: +15 points (if MX exists)
- DNSSEC: +10 points
- **Email detection bonus: +10 points** (if no MX and no email features)

### Performance (100 points max)
- Fast response time (<500ms): +20 points
- Medium response time (<1000ms): +10 points
- GZIP/Brotli compression: +10 points
- Cache-Control and ETag: +5 points

### Vulnerabilities (penalties applied)
- CRITICAL: -20 points
- HIGH: -10 points
- MEDIUM: -5 points
- LOW: -2 points

---

## 📊 Scoring Algorithm

```
Overall Score = (SSL Score + Headers Score + DNS Score + Performance Score) / 4 - Vulnerability Penalties

Risk Level:
- 90-100: INFO
- 80-89: LOW
- 60-79: MEDIUM
- 40-59: HIGH
- 0-39: CRITICAL
```

---

## 🔍 Key Features

### Smart Scoring
- **Email Detection:** Automatically detects if website has email functionality (forms, newsletter, signup)
- **Adaptive DNS Score:** Websites without email get bonus +10 points (not penalized)
- **False Positive Prevention:** Smart content validation for sensitive files
- **Protected Site Detection:** Skips major platforms (GitHub, Google, etc.)

### Real-time Analysis
- Fetches website HTML in real-time
- Analyzes headers, DNS records, SSL certificates
- Detects vulnerabilities using hybrid approach (local database + external API)
- Runs all checks in parallel for speed

### Export Formats
- **Markdown Report:** Full report with executive summary and AI prompts
- **JSON Export:** Structured data for automation and CI/CD
- **CSV Export:** Spreadsheet-friendly format

---

## 🎓 Learning & Education

### OWASP Top 10
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery

### AI Prompts
- Every vulnerability comes with a detailed AI prompt
- Includes code examples (incorrect vs correct)
- Includes best practices and OWASP references
- Includes remediation recommendations
- Perfect for use with AI assistants like ChatGPT, Claude, Cursor

### Resources
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Hacker101](https://www.hacker101.com/)
- [PentesterLab](https://www.pentesterlab.com/)
- [OWASP ZAP](https://www.zaproxy.org/)

### Certifications
- [OSCP](https://www.offensive-security.com/penetration-testing-with-kali-linux/)
- [CEH](https://www.eccouncil.org/programs/certified-ethical-hacker/)
- [CISSP](https://www.isc2.org/certifications/cissp/)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit with descriptive message
5. Push to your fork
6. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨 Authors

- Security Audit Pro Development Team
- Built with Next.js 15 + TypeScript + React 19
- Powered by shadcn/ui + Tailwind CSS 4 + Lucide React
- Vulnerability detection powered by hybrid approach

---

## 🙏 Acknowledgments

- [Next.js](https://nextjs.org/)
- [React](https://react.dev/)
- [shadcn/ui](https://ui.shadcn.com/)
- [Lucide](https://lucide.dev/)
- [Recharts](https://recharts.org/)
- [OWASP](https://owasp.org/)

---

**Made with ❤️ by the Security Audit Pro team**

*Last updated: January 3, 2026*

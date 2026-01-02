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

export type TechStack = 'nextjs-vercel' | 'php-laravel' | 'python-django' | 'java-spring' | 'static-nginx';

// TECH STACKS MATRIX - Universal Security Knowledge Base
const TECH_STACKS_MATRIX = {
  'nextjs-vercel': {
    name: 'Next.js / Vercel / React',
    configFiles: 'next.config.js, vercel.json, middleware.ts',
    headers: {
      locations: 'next.config.js (headers object), vercel.json (routes/headers), public/_headers',
      context: 'Add security headers in next.config.js under headers array or use Vercel Edge Middleware for dynamic headers.'
    },
    serverInfo: {
      locations: 'next.config.js',
      context: 'Set poweredByHeader: false in next.config.js to hide Next.js version disclosure.'
    },
    xssCode: {
      locations: 'src/app/**/*.tsx, src/pages/**/*.jsx, src/components/**/*.tsx',
      context: 'Replace onclick="func()" with onClick={handleClick}. Use React synthetic events. Sanitize HTML with DOMPurify before dangerouslySetInnerHTML.'
    },
    images: {
      locations: 'src/components/**/*.{tsx,jsx}',
      context: 'Use Next.js <Image /> component instead of <img>. Configure domains in next.config.js images.domains for external images.'
    },
    compression: {
      locations: 'vercel.json, next.config.js',
      context: 'Vercel enables compression automatically. Configure next.config.js: compress: true for additional control.'
    },
    caching: {
      locations: 'next.config.js, vercel.json',
      context: 'Configure Cache-Control headers in next.config.js headers array. Use Vercel Edge Middleware for dynamic caching.'
    },
    cors: {
      locations: 'next.config.js, vercel.json, middleware.ts',
      context: 'Configure CORS in next.config.js headers or use Vercel Edge Middleware for API routes.'
    }
  },

  'php-laravel': {
    name: 'PHP / Laravel / Apache',
    configFiles: '.htaccess, httpd.conf, nginx.conf',
    headers: {
      locations: '.htaccess, public/.htaccess, app/Http/Middleware/',
      context: 'Use Header set directives in .htaccess or create Laravel middleware classes in app/Http/Middleware/ for programmatic headers.'
    },
    serverInfo: {
      locations: '.htaccess, httpd.conf',
      context: 'Use Header unset Server in .htaccess or ServerTokens Prod in httpd.conf to hide server information.'
    },
    xssCode: {
      locations: 'resources/views/**/*.blade.php, app/**/*.php, public/**/*.php',
      context: 'Use {{ }} escaping in Blade templates. In raw PHP, use htmlspecialchars() for output. Avoid echo with user input.'
    },
    images: {
      locations: 'resources/views/**/*.blade.php, public/images/',
      context: 'Validate image uploads server-side. Use proper file extensions. Consider image optimization libraries like Intervention Image.'
    },
    compression: {
      locations: '.htaccess, httpd.conf, nginx.conf',
      context: 'Enable mod_deflate in Apache or gzip in nginx. Configure compression levels and file types.'
    },
    caching: {
      locations: '.htaccess, app/Http/Middleware/',
      context: 'Set Cache-Control headers in .htaccess or Laravel middleware. Use proper ETag generation.'
    },
    cors: {
      locations: 'app/Http/Middleware/Cors.php, config/cors.php',
      context: 'Configure CORS in Laravel using config/cors.php or custom middleware for specific routes.'
    }
  },

  'python-django': {
    name: 'Python / Django / Flask',
    configFiles: 'settings.py, wsgi.py, nginx.conf',
    headers: {
      locations: 'settings.py, middleware.py, nginx.conf',
      context: 'Configure SECURE_* settings in settings.py. Use custom middleware classes for additional headers. Configure nginx for proxy headers.'
    },
    serverInfo: {
      locations: 'settings.py, wsgi.py',
      context: 'Remove or modify SERVER header in Django settings. Use custom WSGI middleware if needed.'
    },
    xssCode: {
      locations: 'templates/**/*.html, **/*.py',
      context: 'Ensure auto-escaping is enabled in Django (default). Use |escape filter manually. In Flask, use autoescape=True in render_template.'
    },
    images: {
      locations: 'static/images/, media/images/',
      context: 'Validate image uploads in views.py. Use Django ImageField. Configure file permissions and storage.'
    },
    compression: {
      locations: 'nginx.conf, middleware.py',
      context: 'Enable gzip compression in nginx reverse proxy. Use Django middleware for response compression if needed.'
    },
    caching: {
      locations: 'settings.py, urls.py, nginx.conf',
      context: 'Configure Django caching framework. Set Cache-Control headers in views or nginx. Use ETags for static files.'
    },
    cors: {
      locations: 'settings.py, urls.py, middleware.py',
      context: 'Install django-cors-headers. Configure CORS_ORIGIN_WHITELIST in settings.py or use custom middleware.'
    }
  },

  'java-spring': {
    name: 'Java / Spring Boot / Tomcat',
    configFiles: 'application.properties, application.yml, WebSecurityConfig.java',
    headers: {
      locations: 'WebSecurityConfig.java, application.yml, web.xml',
      context: 'Configure Spring Security httpSecurity.headers() in WebSecurityConfig.java. Use application.yml for additional headers.'
    },
    serverInfo: {
      locations: 'application.properties, server.xml',
      context: 'Configure server.server-header in application.properties or server.xml to hide server information.'
    },
    xssCode: {
      locations: 'src/main/resources/templates/**/*.html, **/*.jsp, **/*.java',
      context: 'Thymeleaf escapes by default. For JSP, use <c:out> or fn:escapeXml(). In Java code, validate and sanitize user input.'
    },
    images: {
      locations: 'src/main/resources/static/images/, **/*.java',
      context: 'Validate file uploads in controllers. Use Spring multipart configuration. Set proper file permissions.'
    },
    compression: {
      locations: 'application.properties, server.xml, nginx.conf',
      context: 'Configure compression in application.properties or nginx reverse proxy. Enable gzip for responses.'
    },
    caching: {
      locations: 'WebConfig.java, application.yml, nginx.conf',
      context: 'Configure Cache-Control headers in Spring MVC config. Use @Cacheable annotations. Set headers in nginx.'
    },
    cors: {
      locations: 'WebSecurityConfig.java, application.yml',
      context: 'Configure CORS in Spring Security with cors() method or @CrossOrigin annotations on controllers.'
    }
  },

  'static-nginx': {
    name: 'Static HTML / Nginx',
    configFiles: 'nginx.conf, conf.d/default.conf',
    headers: {
      locations: 'nginx.conf, .htaccess',
      context: 'Use add_header directives in nginx.conf server block. For Apache, use Header set in .htaccess.'
    },
    serverInfo: {
      locations: 'nginx.conf',
      context: 'Use server_tokens off; in nginx.conf to hide version information.'
    },
    xssCode: {
      locations: 'index.html, **/*.html, **/*.js',
      context: 'Remove onclick="..." entirely. Move JavaScript to external files. Use addEventListener() instead of inline handlers.'
    },
    images: {
      locations: '**/*.html, images/',
      context: 'Use proper image formats. Implement lazy loading. Validate file paths and extensions.'
    },
    compression: {
      locations: 'nginx.conf',
      context: 'Enable gzip on; and configure gzip_types in nginx.conf for HTML, CSS, JS, JSON files.'
    },
    caching: {
      locations: 'nginx.conf, .htaccess',
      context: 'Use expires directives in nginx.conf. Set Cache-Control headers based on file types.'
    },
    cors: {
      locations: 'nginx.conf',
      context: 'Add Access-Control-Allow-Origin and related CORS headers in nginx.conf server block.'
    }
  }
};

// SNIPPET DATABASE - Code Scaffolding for Fixes
const SNIPPET_DATABASE = {
  'Content-Security-Policy': {
    'nextjs-vercel': {
      file: 'next.config.js',
      language: 'javascript',
      code: `// next.config.js
module.exports = {
  // ... other config
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'Content-Security-Policy',
          value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
        }
      ]
    }
  ]
}`
    },
    'php-laravel': {
      file: '.htaccess',
      language: 'apache',
      code: `# .htaccess
<IfModule mod_headers.c>
  Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
</IfModule>`
    },
    'python-django': {
      file: 'settings.py',
      language: 'python',
      code: `# settings.py
# Install django-csp first: pip install django-csp

INSTALLED_APPS = [
    # ... other apps
    'csp',
]

MIDDLEWARE = [
    # ... other middleware
    'csp.middleware.CSPMiddleware',
]

# CSP Settings
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "data:")`
    },
    'java-spring': {
      file: 'WebSecurityConfig.java',
      language: 'java',
      code: `// WebSecurityConfig.java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers(headers ->
                headers
                    .contentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
            );
    }
}`
    },
    'static-nginx': {
      file: 'nginx.conf',
      language: 'nginx',
      code: `# nginx.conf
server {
    # ... other config
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;
}`
    }
  },

  'X-Frame-Options': {
    'nextjs-vercel': {
      file: 'next.config.js',
      language: 'javascript',
      code: `// next.config.js
module.exports = {
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'X-Frame-Options',
          value: 'DENY'
        }
      ]
    }
  ]
}`
    },
    'php-laravel': {
      file: '.htaccess',
      language: 'apache',
      code: `# .htaccess
<IfModule mod_headers.c>
  Header always set X-Frame-Options "DENY"
</IfModule>`
    },
    'python-django': {
      file: 'settings.py',
      language: 'python',
      code: `# settings.py
# Security settings
SECURE_FRAME_DENY = True`
    },
    'java-spring': {
      file: 'WebSecurityConfig.java',
      language: 'java',
      code: `// WebSecurityConfig.java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers(headers ->
                headers.frameOptions().deny()
            );
    }
}`
    },
    'static-nginx': {
      file: 'nginx.conf',
      language: 'nginx',
      code: `# nginx.conf
server {
    add_header X-Frame-Options "DENY" always;
}`
    }
  },

  'Strict-Transport-Security': {
    'nextjs-vercel': {
      file: 'next.config.js',
      language: 'javascript',
      code: `// next.config.js
module.exports = {
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'Strict-Transport-Security',
          value: 'max-age=63072000; includeSubDomains; preload'
        }
      ]
    }
  ]
}`
    },
    'php-laravel': {
      file: '.htaccess',
      language: 'apache',
      code: `# .htaccess
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
</IfModule>`
    },
    'python-django': {
      file: 'settings.py',
      language: 'python',
      code: `# settings.py
# Security settings
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True`
    },
    'java-spring': {
      file: 'application.properties',
      language: 'properties',
      code: `# application.properties
# HSTS settings
server.ssl.enabled=true
server.ssl.hsts.enabled=true
server.ssl.hsts.max-age=63072000
server.ssl.hsts.include-subdomains=true
server.ssl.hsts.preload=true`
    },
    'static-nginx': {
      file: 'nginx.conf',
      language: 'nginx',
      code: `# nginx.conf
server {
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}`
    }
  },

  'Referrer-Policy': {
    'nextjs-vercel': {
      file: 'next.config.js',
      language: 'javascript',
      code: `// next.config.js
module.exports = {
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'Referrer-Policy',
          value: 'strict-origin-when-cross-origin'
        }
      ]
    }
  ]
}`
    },
    'php-laravel': {
      file: '.htaccess',
      language: 'apache',
      code: `# .htaccess
<IfModule mod_headers.c>
  Header set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>`
    },
    'python-django': {
      file: 'settings.py',
      language: 'python',
      code: `# settings.py
# Security settings
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'`
    },
    'java-spring': {
      file: 'application.properties',
      language: 'properties',
      code: `# application.properties
# Referrer Policy settings
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true`
    },
    'static-nginx': {
      file: 'nginx.conf',
      language: 'nginx',
      code: `# nginx.conf
server {
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}`
    }
  },

  'Permissions-Policy': {
    'nextjs-vercel': {
      file: 'next.config.js',
      language: 'javascript',
      code: `// next.config.js
module.exports = {
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'Permissions-Policy',
          value: 'camera=(), microphone=(), geolocation=()'
        }
      ]
    }
  ]
}`
    },
    'php-laravel': {
      file: '.htaccess',
      language: 'apache',
      code: `# .htaccess
<IfModule mod_headers.c>
  Header set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>`
    },
    'python-django': {
      file: 'settings.py',
      language: 'python',
      code: `# settings.py
# Security settings - Django doesn't have built-in Permissions-Policy
# Use django-csp or custom middleware

# Example with django-csp:
CSP_PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=()"`
    },
    'java-spring': {
      file: 'WebSecurityConfig.java',
      language: 'java',
      code: `// WebSecurityConfig.java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers(headers ->
                headers.permissionsPolicy(permissions ->
                    permissions.policy("camera=(), microphone=(), geolocation=()")
                )
            );
    }
}`
    },
    'static-nginx': {
      file: 'nginx.conf',
      language: 'nginx',
      code: `# nginx.conf
server {
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
}`
    }
  },

  'Inline Event Handlers': {
    'nextjs-vercel': {
      file: 'Component.tsx',
      language: 'typescript',
      code: `// ❌ BAD - Inline event handler
<div onClick={() => alert('Hello!')}>Click me</div>

// ✅ GOOD - Proper React event handler
const handleClick = () => {
  alert('Hello!')
}

<div onClick={handleClick}>Click me</div>`
    },
    'php-laravel': {
      file: 'view.blade.php',
      language: 'html',
      code: `{{-- ❌ BAD - Inline JavaScript --}}
<button onclick="alert('Hello!')">Click me</button>

{{-- ✅ GOOD - External JavaScript --}}
<button id="myButton">Click me</button>

<script>
document.getElementById('myButton').addEventListener('click', function() {
    alert('Hello!');
});
</script>`
    },
    'python-django': {
      file: 'template.html',
      language: 'html',
      code: `{# ❌ BAD - Inline event handler #}
<button onclick="alert('Hello!')">Click me</button>

{# ✅ GOOD - Django way #}
<button data-action="click->controller#handleClick">Click me</button>

{# Or use proper event listeners in JavaScript #}
<script>
document.addEventListener('DOMContentLoaded', function() {
    document.querySelector('[data-action]').addEventListener('click', function() {
        alert('Hello!');
    });
});
</script>`
    },
    'java-spring': {
      file: 'template.html',
      language: 'html',
      code: `<!-- ❌ BAD - Inline event handler -->
<button onclick="alert('Hello!')">Click me</button>

<!-- ✅ GOOD - Thymeleaf way -->
<button th:onclick="'javascript:alert(\\'Hello!\\')'">Click me</button>

<!-- Even better: Use proper event listeners -->
<button id="myButton">Click me</button>

<script>
document.getElementById('myButton').addEventListener('click', function() {
    alert('Hello!');
});
</script>`
    },
    'static-nginx': {
      file: 'index.html',
      language: 'html',
      code: `<!-- ❌ BAD - Inline event handler -->
<button onclick="alert('Hello!')">Click me</button>

<!-- ✅ GOOD - External JavaScript -->
<button id="myButton">Click me</button>

<script src="script.js"></script>

<!-- script.js -->
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('myButton').addEventListener('click', function() {
        alert('Hello!');
    });
});`
    }
  }
};

// Universal mappings for all stacks
const UNIVERSAL_MAPPINGS = {
  dns: {
    actionType: 'EXTERNAL_ACTION' as const,
    locations: 'DNS Provider Console (Cloudflare, GoDaddy, AWS Route53)',
    context: 'Add DNS records through your DNS provider dashboard. Test with tools like MX Toolbox or DNS Checker.'
  },
  dependencies: {
    actionType: 'CODE_REFACTOR' as const,
    locations: 'package.json, composer.json, requirements.txt, pom.xml',
    context: 'Update vulnerable dependencies using package managers. Run security audits regularly.'
  },
  gitExposure: {
    actionType: 'CONFIG_CHANGE' as const,
    locations: '.git folder, .gitignore, nginx.conf',
    context: 'Delete .git folder from production or configure server to block .git access. Add .git to .gitignore.'
  }
};

// Dynamic context mapping based on selected tech stack
const CONTEXT_MAP = {
  // SSL/TLS Category
  'SSL/TLS': {
    patterns: ['SSL', 'TLS', 'certificate', 'cipher', 'protocol', 'Mixed Content'],
    getContextForStack: (stack: string, vulnTitle: string) => {
      const stackConfig = TECH_STACKS_MATRIX[stack as keyof typeof TECH_STACKS_MATRIX];
      if (!stackConfig) return { actionType: 'CONFIG_CHANGE', locations: 'Check server configuration', context: 'Review SSL/TLS configuration for your stack' };

      return {
        actionType: 'CONFIG_CHANGE' as const,
        locations: stackConfig.configFiles,
        context: vulnTitle.includes('Mixed Content')
          ? `Search for http:// URLs in HTML templates and replace with https://. Check ${stackConfig.images?.locations || 'static files'} for external resources.`
          : vulnTitle.includes('HTTP Available')
          ? `Configure HTTPS redirects in ${stackConfig.configFiles}.`
          : `Review SSL/TLS configuration in ${stackConfig.configFiles}.`
      };
    }
  },

  // Security Headers Category (CRITICAL)
  'INSECURE_HEADERS': {
    patterns: ['Content-Security-Policy', 'HSTS', 'X-Frame-Options', 'X-Content-Type-Options', 'Permissions-Policy', 'Referrer-Policy'],
    getContextForStack: (stack: string, vulnTitle: string) => {
      const stackConfig = TECH_STACKS_MATRIX[stack as keyof typeof TECH_STACKS_MATRIX];
      if (!stackConfig) return { actionType: 'CONFIG_CHANGE', locations: 'Check server configuration', context: 'Configure security headers for your stack' };

      return {
        actionType: 'CONFIG_CHANGE' as const,
        locations: stackConfig.headers.locations,
        context: stackConfig.headers.context
      };
    }
  },

  // DNS & Email Security Category
  'DNS': {
    patterns: ['SPF', 'DMARC', 'DKIM', 'DNSSEC'],
    getContextForStack: (stack: string, vulnTitle: string) => {
      return {
        actionType: 'EXTERNAL_ACTION' as const,
        locations: UNIVERSAL_MAPPINGS.dns.locations,
        context: UNIVERSAL_MAPPINGS.dns.context
      };
    }
  },

  // Performance Category
  'PERFORMANCE': {
    patterns: ['Gzip', 'Brotli', 'compression', 'caching', 'images', 'render blocking'],
    getContextForStack: (stack: string, vulnTitle: string) => {
      const stackConfig = TECH_STACKS_MATRIX[stack as keyof typeof TECH_STACKS_MATRIX];
      if (!stackConfig) return { actionType: 'CONFIG_CHANGE', locations: 'Check server configuration', context: 'Configure performance optimizations' };

      if (vulnTitle.includes('Gzip') || vulnTitle.includes('compression')) {
        return {
          actionType: 'CONFIG_CHANGE' as const,
          locations: stackConfig.compression.locations,
          context: stackConfig.compression.context
        };
      }
      if (vulnTitle.includes('Cache')) {
        return {
          actionType: 'CONFIG_CHANGE' as const,
          locations: stackConfig.caching.locations,
          context: stackConfig.caching.context
        };
      }
      if (vulnTitle.includes('images')) {
        return {
          actionType: 'CONFIG_CHANGE' as const,
          locations: stackConfig.images.locations,
          context: stackConfig.images.context
        };
      }

      return {
        actionType: 'CONFIG_CHANGE' as const,
        locations: stackConfig.configFiles,
        context: 'Review performance configuration for your stack'
      };
    }
  },

  // XSS & Injection Vulnerabilities
  'XSS': {
    patterns: ['inline event handler', 'javascript:', 'innerHTML', 'dangerouslySetInnerHTML'],
    getContextForStack: (stack: string, vulnTitle: string) => {
      const stackConfig = TECH_STACKS_MATRIX[stack as keyof typeof TECH_STACKS_MATRIX];
      if (!stackConfig) return { actionType: 'CODE_REFACTOR', locations: 'Check source code', context: 'Review XSS vulnerabilities in your code' };

      return {
        actionType: 'CODE_REFACTOR' as const, // Правильный тип действия
        locations: stackConfig.xssCode.locations,
        context: stackConfig.xssCode.context
      };
    }
  },

  // Information Disclosure
  'INFORMATION_DISCLOSURE': {
    patterns: ['Server header', 'technology disclosure', 'meta author', 'version disclosure'],
    getContextForStack: (stack: string, vulnTitle: string) => {
      const stackConfig = TECH_STACKS_MATRIX[stack as keyof typeof TECH_STACKS_MATRIX];
      if (!stackConfig) return { actionType: 'CONFIG_CHANGE', locations: 'Check configuration', context: 'Review information disclosure settings' };

      if (vulnTitle.includes('Server header')) {
        return {
          actionType: 'CONFIG_CHANGE' as const,
          locations: stackConfig.serverInfo.locations,
          context: stackConfig.serverInfo.context
        };
      }

      return {
        actionType: 'CONFIG_CHANGE' as const,
        locations: 'src/app/layout.tsx, public/index.html, package.json',
        context: 'Remove or anonymize meta tags and version information that disclose implementation details.'
      };
    }
  },

  // Misc Configuration Issues
  'MISCONFIGURATION': {
    patterns: ['CORS', 'Open Graph', 'Robots.txt', 'WAF'],
    getContextForStack: (stack: string, vulnTitle: string) => {
      const stackConfig = TECH_STACKS_MATRIX[stack as keyof typeof TECH_STACKS_MATRIX];
      if (!stackConfig) return { actionType: 'CONFIG_CHANGE', locations: 'Check configuration', context: 'Review configuration settings' };

      if (vulnTitle.includes('CORS')) {
        return {
          actionType: 'CONFIG_CHANGE' as const,
          locations: stackConfig.cors.locations,
          context: stackConfig.cors.context
        };
      }

      return {
        actionType: 'CONFIG_CHANGE' as const,
        locations: stackConfig.configFiles,
        context: 'Review configuration settings for your stack'
      };
    }
  }
};

export class SecurityReportEnricher {
  private report: SecurityReport;
  private techStack: TechStack;
  private detectedStack: TechStack;

  constructor(report: SecurityReport, techStack: TechStack = 'nextjs-vercel') {
    this.report = report;
    this.techStack = techStack;
    this.detectedStack = this.autoDetectStack();
  }

  /**
   * Auto-detect technology stack from report content using regex patterns
   */
  private autoDetectStack(): TechStack {
    const reportText = JSON.stringify(this.report).toLowerCase();

    // Stack detection patterns (most specific first)
    const stackPatterns = [
      {
        stack: 'static-nginx' as TechStack,
        patterns: ['nginx', 'static html', 'apache', 'html', 'javascript:', 'onclick='],
        weight: 1
      },
      {
        stack: 'java-spring' as TechStack,
        patterns: ['java', 'spring', 'tomcat', 'jsp', 'thymeleaf', 'websecurityconfig'],
        weight: 3
      },
      {
        stack: 'python-django' as TechStack,
        patterns: ['python', 'django', 'flask', 'jinja', 'settings.py', 'wsgi'],
        weight: 3
      },
      {
        stack: 'php-laravel' as TechStack,
        patterns: ['php', 'laravel', 'apache', 'composer', 'blade', '.htaccess'],
        weight: 3
      },
      {
        stack: 'nextjs-vercel' as TechStack,
        patterns: ['next.js', 'vercel', 'react', 'next.config.js', 'middleware.ts', 'app router'],
        weight: 3
      }
    ];

    // Calculate scores for each stack
    const scores = stackPatterns.map(({ stack, patterns, weight }) => {
      let score = 0;
      patterns.forEach(pattern => {
        // Count occurrences of each pattern
        const regex = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        const matches = reportText.match(regex);
        if (matches && matches.length > 0) {
          score += matches.length * weight;
        }
      });
      return { stack, score };
    });

    // Return stack with highest score, fallback to provided techStack
    const bestMatch = scores.reduce((best, current) =>
      current.score > best.score ? current : best
    );

    return bestMatch.score > 0 ? bestMatch.stack : this.techStack;
  }

  /**
   * Get detected stack info
   */
  getDetectedStack(): { stack: TechStack; name: string; confidence: 'high' | 'medium' | 'low' } {
    const stackConfig = TECH_STACKS_MATRIX[this.detectedStack];

    // Calculate confidence based on detection score
    const reportText = JSON.stringify(this.report).toLowerCase();
    let confidenceScore = 0;

    // Use the same patterns from autoDetectStack for confidence calculation
    const allStackPatterns = [
      ...['nextjs-vercel'].map(s => ({ stack: s, patterns: ['next.js', 'vercel', 'react', 'next.config.js', 'middleware.ts', 'app router'] })),
      ...['python-django'].map(s => ({ stack: s, patterns: ['python', 'django', 'flask', 'jinja', 'settings.py', 'wsgi'] })),
      ...['php-laravel'].map(s => ({ stack: s, patterns: ['php', 'laravel', 'apache', 'composer', 'blade', '.htaccess'] })),
      ...['java-spring'].map(s => ({ stack: s, patterns: ['java', 'spring', 'tomcat', 'jsp', 'thymeleaf', 'websecurityconfig'] })),
      ...['static-nginx'].map(s => ({ stack: s, patterns: ['nginx', 'static html', 'apache', 'html', 'javascript:', 'onclick='] })),
    ];

    allStackPatterns.forEach(({ patterns }) => {
      patterns.forEach(pattern => {
        if (reportText.includes(pattern.toLowerCase())) {
          confidenceScore += 2;
        }
      });
    });

    let confidence: 'high' | 'medium' | 'low' = 'low';
    if (confidenceScore >= 6) confidence = 'high';
    else if (confidenceScore >= 3) confidence = 'medium';

    return {
      stack: this.detectedStack,
      name: stackConfig?.name || 'Unknown',
      confidence
    };
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
   * Determine action type and context based on vulnerability type and tech stack
   */
  private getContextForVulnerability(vuln: Vulnerability): {
    actionType: 'CODE_REFACTOR' | 'CONFIG_CHANGE' | 'EXTERNAL_ACTION';
    locations: string;
    context: string;
  } {
    // Find matching category
    for (const [category, config] of Object.entries(CONTEXT_MAP)) {
      const patterns = (config as any).patterns;
      if (patterns && patterns.some((pattern: string) =>
        (vuln.type && vuln.type.toLowerCase().includes(pattern.toLowerCase())) ||
        (vuln.title && vuln.title.toLowerCase().includes(pattern.toLowerCase())) ||
        (vuln.description && vuln.description.toLowerCase().includes(pattern.toLowerCase()))
      )) {
        // Use the getContextForStack method with selected tech stack
        return (config as any).getContextForStack(this.techStack, vuln.title);
      }
    }

    // Default fallback based on tech stack
    const stackConfig = TECH_STACKS_MATRIX[this.techStack];
    return {
      actionType: 'CONFIG_CHANGE',
      locations: stackConfig?.configFiles || 'Check configuration files',
      context: `Review vulnerability details and determine appropriate configuration changes for ${stackConfig?.name || 'your tech stack'}.`
    };
  }

  /**
   * Get code scaffolding for a specific vulnerability and tech stack
   */
  private getCodeScaffolding(vuln: Vulnerability): { file: string; language: string; code: string } | null {
    // Find matching vulnerability in SNIPPET_DATABASE
    for (const [vulnKey, stacks] of Object.entries(SNIPPET_DATABASE)) {
      if (vuln.title.toLowerCase().includes(vulnKey.toLowerCase())) {
        const stackSnippet = stacks[this.detectedStack as keyof typeof stacks];
        if (stackSnippet) {
          return stackSnippet;
        }
      }
    }

    // Try broader matching for XSS vulnerabilities
    if (vuln.type === 'XSS' || vuln.title.toLowerCase().includes('inline')) {
      const xssSnippet = SNIPPET_DATABASE['Inline Event Handlers']?.[this.detectedStack as keyof typeof SNIPPET_DATABASE['Inline Event Handlers']];
      if (xssSnippet) {
        return xssSnippet;
      }
    }

    return null;
  }

  /**
   * Generate enriched AI prompt for a single vulnerability
   */
  private generateEnrichedPrompt(vuln: Vulnerability, index: number): EnrichedPrompt {
    const context = this.getContextForVulnerability(vuln);
    const scaffolding = this.getCodeScaffolding(vuln);

    let scaffoldingText = '';
    if (scaffolding) {
      scaffoldingText = `

**FIX IMPLEMENTATION (CODE SCAFFOLDING):**
Here is the exact code pattern you should apply. Integrate this into the file ${scaffolding.file}.

\`\`\`${scaffolding.language}
${scaffolding.code}
\`\`\`

**Integration Instructions:**
1. Locate the file: ${scaffolding.file}
2. Add or modify the configuration as shown in the scaffolding above
3. Ensure proper syntax and indentation
4. Test the configuration after applying`;
    }

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
4. Explain briefly what you changed and why.${scaffoldingText}

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

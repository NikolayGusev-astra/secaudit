export type Language = 'ru' | 'en'

export const translations = {
  ru: {
    // UI элементы
    appTitle: 'Security Audit for VibeCoders',
    appDescription: 'Профессиональный инструмент для сканирования безопасности. Анализируйте сайты на уязвимости, неправильно настроенную безопасность и проблемы производительности.',
    
    // Основные элементы
    scanner: 'Сканер безопасности веб-сайтов',
    scannerDesc: 'Введите URL для комплексного аудита безопасности и производительности',
    placeholder: 'example.com или https://example.com',
    checkSecurity: 'Проверить безопасность',
    scanning: 'Сканирование...',
    
    // Результаты
    securityResults: 'Результаты оценки безопасности',
    target: 'Цель',
    domain: 'Домен',
    securityScore: 'Оценка безопасности',
    export: 'Экспорт',
    
    // Вкладки
    overview: 'Обзор',
    ssl: 'SSL/TLS',
    headers: 'Заголовки',
    dns: 'DNS',
    performance: 'Производительность',
    vulnerabilities: 'Уязвимости',
    
    // Категории оценок
    sslTls: 'SSL/TLS',
    securityHeaders: 'Security Headers',
    dnsSecurityCategory: 'DNS Security',
    perfCategory: 'Производительность',
    
    // DNS детали
    dnsSecurityConfig: 'Конфигурация безопасности DNS',
    whatIs: 'Что это?',
    whatFor: 'Для чего нужно?',
    risks: 'Риски отсутствия',
    recommendation: 'Рекомендация',
    whereToConfigure: 'Где настроить',
    
    // SPF
    spfTitle: 'SPF (Sender Policy Framework)',
    spfDesc: 'Механизм валидации отправителя email',
    spfPurpose: 'Защита от подделки email от имени вашего домена и защита от попадания в спам',
    spfRisks: 'Email могут подделать злоумышленники, письма попадут в спам, потеря доверия получателей',
    spfRecommendation: 'Добавить TXT запись: v=spf1 include:_spf.google.com ~all',
    spfWhere: 'Панель управления DNS хостинг-провайдера',
    
    // DMARC
    dmarcTitle: 'DMARC (Domain-based Message Authentication)',
    dmarcDesc: 'Политика обработки SPF/DKIM результатов',
    dmarcPurpose: 'Контроль над не прошедшими проверку email и получение отчетов о попытках подделки',
    dmarcRisks: 'Нет контроля над поддельными email, отсутствие отчетов о попытках подделки',
    dmarcRecommendation: 'Начать с p=none для мониторинга, затем p=quarantine или p=reject',
    dmarcWhere: 'DNS TXT запись _dmarc.yourdomain.com',
    
    // DKIM
    dkimTitle: 'DKIM (DomainKeys Identified Mail)',
    dkimDesc: 'Криптографическая цифровая подпись email',
    dkimPurpose: 'Гарантирует что email не был изменен в пути от отправителя к получателю',
    dkimRisks: 'Email могут быть подделаны, нет гарантии целостности содержимого',
    dkimRecommendation: 'Настроить на почтовом сервере (Google Workspace, Postfix, Microsoft 365 и т.д.)',
    dkimWhere: 'Почтовый сервер + DNS TXT запись с публичным ключом',
    
    // DNSSEC
    dnssecTitle: 'DNSSEC (DNS Security Extensions)',
    dnssecDesc: 'Криптографическая защита DNS записей',
    dnssecPurpose: 'Защита от DNS spoofing, cache poisoning и других атак на DNS инфраструктуру',
    dnssecRisks: 'Атакующие могут перенаправлять пользователей на фишинговые сайты, перехват DNS запросов',
    dnssecRecommendation: 'Включить на регистраторе домена (требуется поддержка регистратором)',
    dnssecWhere: 'Панель регистратора домена (обязательно проверить совместимость регистратора)',
    
    // SSL/TLS детали
    sslCertificate: 'SSL/TLS Сертификат',
    certificatePresent: 'Сертификат присутствует',
    certificateValid: 'Сертификат валидный',
    issuer: 'Удостоверяющий центр',
    tlsVersion: 'Версия TLS',
    validFrom: 'Действует с',
    validTo: 'Действует до',
    daysUntilExpiry: 'Дней до окончания',
    expiringSoon: 'Истекает скоро',
    
    // Headers детали
    securityHeadersAnalysis: 'Анализ Security Headers',
    headersScore: 'Оценка',
    missingHeaders: 'Отсутствующие заголовки безопасности',
    
    // CSP
    cspTitle: 'Content-Security-Policy (CSP)',
    cspDesc: 'Ограничивает ресурсы которые могут быть загружены на странице',
    cspPurpose: 'Защищает от XSS атак, инъекций кода и загрузки вредоносных ресурсов',
    cspRisks: 'Отсутствие CSP позволяет злоумышленникам внедрять вредоносные скрипты и steal данные',
    cspRecommendation: 'Начать с: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://cdn.example.com',
    cspCode: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;`,
    cspHowTo: 'Добавить в Next.js middleware или server headers',
    
    // HSTS
    hstsTitle: 'Strict-Transport-Security (HSTS)',
    hstsDesc: 'Принудительно использует HTTPS соединение',
    hstsPurpose: 'Защищает от downgrade attacks когда атакующий пытается переключить соединение на HTTP',
    hstsRisks: 'Отсутствие HSTS позволяет атакующим перехватывать незашифрованный трафик',
    hstsRecommendation: 'Использовать: max-age=31536000; includeSubDomains; preload (для критически важных систем)',
    hstsCode: `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
    hstsHowTo: 'Добавить в server headers или middleware',
    
    // X-Frame-Options
    xFrameTitle: 'X-Frame-Options',
    xFrameDesc: 'Предотвращает загрузку страницы в iframe',
    xFramePurpose: 'Защищает от clickjacking атак когда злоумышленник накрывает сайт прозрачным фреймом',
    xFrameRisks: 'Отсутствие позволяет clickjacking - пользователи нажимают не на те кнопки',
    xFrameRecommendation: 'Использовать: DENY или SAMEORIGIN',
    xFrameCode: `X-Frame-Options: DENY`,
    xFrameHowTo: 'Добавить в security headers или использовать CSP frame-ancestors',
    
    // Performance детали
    performanceAnalysis: 'Анализ производительности',
    httpStatus: 'HTTP статус',
    responseTime: 'Время ответа',
    gzipCompression: 'GZIP сжатие',
    http2OrHttp3: 'HTTP/2 или HTTP/3',
    
    // Vulnerabilities
    vulnerabilitiesFound: 'Найдено уязвимостей',
    noVulnerabilities: 'Уязвимости не найдены',
    noVulnerabilitiesDesc: 'Отличная работа! Ваш сайт прошел все проверки безопасности.',
    detailedReport: 'Детальный отчет об уязвимостях',
    vulnerabilityType: 'Тип уязвимости',
    
    // Типы уязвимостей
    missingCSP: 'Отсутствует Content-Security-Policy',
    missingCSPDesc: 'Content-Security-Policy заголовок не настроен',
    missingCSPRecommendation: 'Добавить CSP заголовок для защиты от XSS атак',
    
    missingHSTS: 'Отсутствует HSTS',
    missingHSTSDesc: 'Strict-Transport-Security заголовок не настроен',
    missingHSTSRecommendation: 'Добавить HSTS для принудительного использования HTTPS',
    
    missingXFrameOptions: 'Отсутствует X-Frame-Options',
    missingXFrameOptionsDesc: 'X-Frame-Options заголовок не настроен',
    missingXFrameOptionsRecommendation: 'Добавить X-Frame-Options для защиты от clickjacking',
    
    sensitiveFileExposed: 'Обнаружен чувствительный файл',
    sensitiveFileExposedDesc: 'Файл {file} доступен через web',
    sensitiveFileExposedRecommendation: 'Удалить файл из production или настроить сервер для блокировки доступа',
    
    corsMisconfig: 'Неправильная конфигурация CORS',
    corsMisconfigDesc: 'Использование wildcard origin (*) с credentials',
    corsMisconfigRecommendation: 'Заменить wildcard на конкретные разрешенные origins',
    
    missingSRI: 'Отсутствует Subresource Integrity (SRI)',
    missingSRIDesc: 'Внешние скрипты не имеют integrity атрибута',
    missingSRIRecommendation: 'Добавить SRI для внешних ресурсов',
    
    inlineEventHandlers: 'Inline event handlers обнаружены',
    inlineEventHandlersDesc: 'Обнаружено {count} inline event handler(s)',
    inlineEventHandlersRecommendation: 'Убрать inline обработчики и использовать event listeners',
    
    mixedContent: 'Обнаружен mixed content',
    mixedContentDesc: 'HTTPS страница загружает HTTP ресурсы',
    mixedContentRecommendation: 'Все ресурсы должны быть по HTTPS',
    
    insecureForm: 'Небезопасная форма',
    insecureFormDesc: 'Форма отправляет данные на HTTP',
    insecureFormRecommendation: 'Изменить action на HTTPS',
    
    // Формат рекомендаций
    problem: 'Проблема',
    stepsToFix: 'Шаги для исправления',
    codeExample: 'Пример кода',
    learnMore: 'Подробнее',
    
    // Степени риска
    critical: 'КРИТИЧЕСКИЙ',
    high: 'ВЫСОКИЙ',
    medium: 'СРЕДНИЙ',
    low: 'НИЗКИЙ',
    info: 'ИНФОРМАЦИЯ',
    
    // Export
    markdownReport: 'Markdown отчет',
    jsonExport: 'JSON экспорт',
    csvExport: 'CSV экспорт',
    
    // Footer
    footer: 'Профессиональный инструмент аудита безопасности • Сканируйте сайты на уязвимости и проблемы производительности',
    
    // Ошибки
    error: 'Ошибка',
    pleaseEnterUrl: 'Пожалуйста, введите URL',
    invalidUrl: 'Пожалуйста, введите корректный URL',
    scanFailed: 'Не удалось просканировать веб-сайт. Пожалуйста, попробуйте снова.',
    downloadFailed: 'Не удалось скачать отчет. Пожалуйста, попробуйте снова.',
    
    // Защищенные сайты
    protectedSite: 'Обнаружен защищенный сайт',
    protectedSiteDesc: 'Это крупная платформа с корпоративной защитой. Стандартные проверки уязвимостей не применимы.',
    protectedSiteRecommendation: 'Крупные платформы имеют собственные команды безопасности и системы мониторинга.',
    
    // WAF
    wafDetected: 'Обнаружен WAF',
    wafDetectedDesc: 'Веб-сайт защищен {waf}',
    wafDetectedRecommendation: 'Убедитесь что правила WAF регулярно обновляются',
    noWaf: 'WAF не обнаружен',
    noWafDesc: 'Не обнаружен Web Application Firewall',
    noWafRecommendation: 'Рассмотрите внедрение WAF (Cloudflare, AWS WAF, ModSecurity и т.д.) для защиты от автоматизированных атак',
    
    // Общее
    yes: 'Да',
    no: 'Нет',
    scoreOutOf100: '/100',
    days: 'дней',
  },
  en: {
    // UI элементы
    appTitle: 'Security Audit for VibeCoders',
    appDescription: 'Professional-grade security and performance scanner. Analyze your website for vulnerabilities, security misconfigurations, and performance issues.',
    
    // Основные элементы
    scanner: 'Website Security Scanner',
    scannerDesc: 'Enter a website URL to perform a comprehensive security and performance audit',
    placeholder: 'example.com or https://example.com',
    checkSecurity: 'Check Security',
    scanning: 'Scanning...',
    
    // Результаты
    securityResults: 'Security Assessment Results',
    target: 'Target',
    domain: 'Domain',
    securityScore: 'Security Score',
    export: 'Export',
    
    // Вкладки
    overview: 'Overview',
    ssl: 'SSL/TLS',
    headers: 'Headers',
    dns: 'DNS',
    performance: 'Performance',
    vulnerabilities: 'Vulnerabilities',
    
    // Категории оценок
    sslTls: 'SSL/TLS',
    securityHeaders: 'Security Headers',
    dnsSecurityCategory: 'DNS Security',
    perfCategory: 'Performance',
    
    // DNS детали
    dnsSecurityConfig: 'DNS Security Configuration',
    whatIs: 'What is it?',
    whatFor: 'What is it for?',
    risks: 'Risks if missing',
    recommendation: 'Recommendation',
    whereToConfigure: 'Where to configure',
    
    // SPF
    spfTitle: 'SPF (Sender Policy Framework)',
    spfDesc: 'Email sender validation mechanism',
    spfPurpose: 'Protects against email spoofing and spam from your domain',
    spfRisks: 'Attackers can spoof email, messages go to spam, loss of recipient trust',
    spfRecommendation: 'Add TXT record: v=spf1 include:_spf.google.com ~all',
    spfWhere: 'DNS management panel of your hosting provider',
    
    // DMARC
    dmarcTitle: 'DMARC (Domain-based Message Authentication)',
    dmarcDesc: 'Policy for handling SPF/DKIM results',
    dmarcPurpose: 'Control over failed email verification and receive spoofing attempt reports',
    dmarcRisks: 'No control over spoofed email, no reports on spoofing attempts',
    dmarcRecommendation: 'Start with p=none for monitoring, then p=quarantine or p=reject',
    dmarcWhere: 'DNS TXT record _dmarc.yourdomain.com',
    
    // DKIM
    dkimTitle: 'DKIM (DomainKeys Identified Mail)',
    dkimDesc: 'Cryptographic digital email signature',
    dkimPurpose: 'Guarantees email was not altered in transit from sender to recipient',
    dkimRisks: 'Email can be spoofed, no guarantee of content integrity',
    dkimRecommendation: 'Configure on mail server (Google Workspace, Postfix, Microsoft 365, etc.)',
    dkimWhere: 'Mail server + DNS TXT record with public key',
    
    // DNSSEC
    dnssecTitle: 'DNSSEC (DNS Security Extensions)',
    dnssecDesc: 'Cryptographic protection of DNS records',
    dnssecPurpose: 'Protects against DNS spoofing, cache poisoning, and other DNS infrastructure attacks',
    dnssecRisks: 'Attackers can redirect users to phishing sites, intercept DNS queries',
    dnssecRecommendation: 'Enable on domain registrar (requires registrar support)',
    dnssecWhere: 'Domain registrar panel (must verify registrar compatibility)',
    
    // SSL/TLS детали
    sslCertificate: 'SSL/TLS Certificate',
    certificatePresent: 'Certificate Present',
    certificateValid: 'Valid Certificate',
    issuer: 'Certificate Authority',
    tlsVersion: 'TLS Version',
    validFrom: 'Valid From',
    validTo: 'Valid To',
    daysUntilExpiry: 'Days Until Expiry',
    expiringSoon: 'Expiring Soon',
    
    // Headers детали
    securityHeadersAnalysis: 'Security Headers Analysis',
    headersScore: 'Score',
    missingHeaders: 'Missing Security Headers',
    
    // CSP
    cspTitle: 'Content-Security-Policy (CSP)',
    cspDesc: 'Restricts resources that can be loaded on the page',
    cspPurpose: 'Protects against XSS attacks, code injection, and malicious resource loading',
    cspRisks: 'Missing CSP allows attackers to inject malicious scripts and steal data',
    cspRecommendation: 'Start with: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://cdn.example.com',
    cspCode: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;`,
    cspHowTo: 'Add to Next.js middleware or server headers',
    
    // HSTS
    hstsTitle: 'Strict-Transport-Security (HSTS)',
    hstsDesc: 'Forces HTTPS connection',
    hstsPurpose: 'Protects against downgrade attacks when attacker tries to switch to HTTP',
    hstsRisks: 'Missing HSTS allows attackers to intercept unencrypted traffic',
    hstsRecommendation: 'Use: max-age=31536000; includeSubDomains; preload (for critical systems)',
    hstsCode: `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
    hstsHowTo: 'Add to server headers or middleware',
    
    // X-Frame-Options
    xFrameTitle: 'X-Frame-Options',
    xFrameDesc: 'Prevents page loading in iframe',
    xFramePurpose: 'Protects against clickjacking when attacker covers site with transparent frame',
    xFrameRisks: 'Missing allows clickjacking - users click on wrong buttons',
    xFrameRecommendation: 'Use: DENY or SAMEORIGIN',
    xFrameCode: `X-Frame-Options: DENY`,
    xFrameHowTo: 'Add to security headers or use CSP frame-ancestors',
    
    // Performance детали
    performanceAnalysis: 'Performance Analysis',
    httpStatus: 'HTTP Status',
    responseTime: 'Response Time',
    gzipCompression: 'GZIP Compression',
    http2OrHttp3: 'HTTP/2 or HTTP/3',
    
    // Vulnerabilities
    vulnerabilitiesFound: 'Vulnerabilities Found',
    noVulnerabilities: 'No Vulnerabilities Found',
    noVulnerabilitiesDesc: 'Great job! Your website passed all security checks.',
    detailedReport: 'Detailed Vulnerability Report',
    vulnerabilityType: 'Vulnerability Type',
    
    // Типы уязвимостей
    missingCSP: 'Missing Content-Security-Policy',
    missingCSPDesc: 'Content-Security-Policy header is not configured',
    missingCSPRecommendation: 'Add CSP header to protect against XSS attacks',
    
    missingHSTS: 'Missing HSTS',
    missingHSTSDesc: 'Strict-Transport-Security header is not configured',
    missingHSTSRecommendation: 'Add HSTS to enforce HTTPS usage',
    
    missingXFrameOptions: 'Missing X-Frame-Options',
    missingXFrameOptionsDesc: 'X-Frame-Options header is not configured',
    missingXFrameOptionsRecommendation: 'Add X-Frame-Options to protect against clickjacking',
    
    sensitiveFileExposed: 'Sensitive File Exposed',
    sensitiveFileExposedDesc: 'File {file} is accessible via web',
    sensitiveFileExposedRecommendation: 'Remove file from production or configure server to block access',
    
    corsMisconfig: 'CORS Misconfiguration',
    corsMisconfigDesc: 'Using wildcard origin (*) with credentials',
    corsMisconfigRecommendation: 'Replace wildcard with specific allowed origins',
    
    missingSRI: 'Missing Subresource Integrity (SRI)',
    missingSRIDesc: 'External scripts lack integrity attribute',
    missingSRIRecommendation: 'Add SRI for external resources',
    
    inlineEventHandlers: 'Inline Event Handlers Detected',
    inlineEventHandlersDesc: 'Found {count} inline event handler(s)',
    inlineEventHandlersRecommendation: 'Remove inline handlers and use event listeners',
    
    mixedContent: 'Mixed Content Detected',
    mixedContentDesc: 'HTTPS page loads HTTP resources',
    mixedContentRecommendation: 'All resources must use HTTPS',
    
    insecureForm: 'Insecure Form',
    insecureFormDesc: 'Form submits data to HTTP',
    insecureFormRecommendation: 'Change action to HTTPS',
    
    // Формат рекомендаций
    problem: 'Problem',
    stepsToFix: 'Steps to Fix',
    codeExample: 'Code Example',
    learnMore: 'Learn More',
    
    // Степени риска
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
    info: 'INFO',
    
    // Export
    markdownReport: 'Markdown Report',
    jsonExport: 'JSON Export',
    csvExport: 'CSV Export',
    
    // Footer
    footer: 'Professional Security Audit Tool • Scan your websites for vulnerabilities and performance issues',
    
    // Ошибки
    error: 'Error',
    pleaseEnterUrl: 'Please enter a URL',
    invalidUrl: 'Please enter a valid URL',
    scanFailed: 'Failed to scan website. Please try again.',
    downloadFailed: 'Failed to download report. Please try again.',
    
    // Защищенные сайты
    protectedSite: 'Protected Site Detected',
    protectedSiteDesc: 'This is a major platform with enterprise-grade security. Standard vulnerability checks are not applicable.',
    protectedSiteRecommendation: 'Major platforms have their own security teams and monitoring systems.',
    
    // WAF
    wafDetected: 'WAF Detected',
    wafDetectedDesc: 'Website is protected by {waf}',
    wafDetectedRecommendation: 'Ensure WAF rules are regularly updated',
    noWaf: 'No WAF Detected',
    noWafDesc: 'No Web Application Firewall detected',
    noWafRecommendation: 'Consider implementing a WAF (Cloudflare, AWS WAF, ModSecurity, etc.) to protect against automated attacks',
    
    // Общее
    yes: 'Yes',
    no: 'No',
    scoreOutOf100: '/100',
    days: 'days',
  },
}

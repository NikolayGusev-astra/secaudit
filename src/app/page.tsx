'use client'

import { useState, useCallback } from 'react'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, AlertTriangle, CheckCircle, XCircle, Clock, Server, Globe, Lock, Zap, Eye, Bug, Mail, Key, Download, FileText, Database, Languages, Info } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useLanguage } from '@/lib/language-context'

interface SecurityScan {
  id: string
  url: string
  domain: string
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
  overallScore: number
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNKNOWN'
  startedAt: string
  completedAt?: string
  sslCheck?: SSLCheck
  headersCheck?: SecurityHeaderCheck
  dnsCheck?: DNSCheck
  performance?: PerformanceCheck
  vulnerabilities?: VulnerabilityCheck[]
  portScans?: PortScan[]
}

interface SSLCheck {
  hasCertificate: boolean
  isValid: boolean
  issuer?: string
  validFrom?: string
  validTo?: string
  daysUntilExpiry?: number
  tlsVersion?: string
  score: number
}

interface SecurityHeaderCheck {
  hasCSP: boolean
  hasHSTS: boolean
  hasXFrameOptions: boolean
  hasXSSProtection: boolean
  score: number
  missingHeaders?: string[]
}

interface DNSCheck {
  hasSPF: boolean
  hasDMARC: boolean
  hasDKIM: boolean
  hasDNSSEC: boolean
  hasMXRecord?: boolean
  score: number
}

interface PerformanceCheck {
  statusCode: number
  responseTime: number
  ttfb?: number
  hasGzip: boolean
  httpVersion?: string
  score: number
}

interface VulnerabilityCheck {
  type: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  title: string
  description: string
  recommendation: string
}

interface PortScan {
  port: number
  state: string
  service?: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  description?: string
}

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'CRITICAL': return 'bg-red-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.5)]'
    case 'HIGH': return 'bg-orange-600 text-white shadow-[0_0_15px_rgba(249,115,22,0.5)]'
    case 'MEDIUM': return 'bg-yellow-600 text-white shadow-[0_0_15px_rgba(234,179,8,0.5)]'
    case 'LOW': return 'bg-green-600 text-white shadow-[0_0_15px_rgba(34,197,94,0.5)]'
    case 'INFO': return 'bg-gray-600 text-white shadow-[0_0_15px_rgba(107,114,128,0.5)]'
    default: return 'bg-gray-400 text-white'
  }
}

const getRiskIcon = (riskLevel: string) => {
  switch (riskLevel) {
    case 'CRITICAL':
    case 'HIGH':
      return <XCircle className="h-5 w-5 text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
    case 'MEDIUM':
      return <AlertTriangle className="h-5 w-5 text-yellow-500 drop-shadow-[0_0_8px_rgba(234,179,8,0.8)]" />
    case 'LOW':
      return <Clock className="h-5 w-5 text-orange-500 drop-shadow-[0_0_8px_rgba(249,115,22,0.8)]" />
    case 'INFO':
      return <Eye className="h-5 w-5 text-gray-400" />
    default:
      return <CheckCircle className="h-5 w-5 text-green-500 drop-shadow-[0_0_8px_rgba(34,197,94,0.8)]" />
  }
}

const getScoreColor = (score: number) => {
  if (score >= 80) return 'text-green-400 drop-shadow-[0_0_8px_rgba(34,197,94,0.8)]'
  if (score >= 60) return 'text-yellow-400 drop-shadow-[0_0_8px_rgba(234,179,8,0.8)]'
  if (score >= 40) return 'text-orange-400 drop-shadow-[0_0_8px_rgba(249,115,22,0.8)]'
  return 'text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.8)]'
}

export default function SecurityAuditTool() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanResult, setScanResult] = useState<SecurityScan | null>(null)
  const [error, setError] = useState('')
  const { language, setLanguage, t } = useLanguage()

  const handleDownloadMarkdown = useCallback(() => downloadReport('md'), [scanResult])
  const handleDownloadJSON = useCallback(() => downloadReport('json'), [scanResult])
  const handleDownloadCSV = useCallback(() => downloadReport('csv'), [scanResult])

  const downloadReport = async (format: 'md' | 'json' | 'csv') => {
    if (!scanResult) return

    try {
      if (format === 'md') {
        const response = await fetch('/api/security/report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ ...scanResult, language }),
        })
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `security-report-${scanResult.domain}.md`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      } else if (format === 'json') {
        const jsonData = {
          scan: scanResult,
          aiPrompts: scanResult.vulnerabilities?.map((v: any) => ({
            issue: v.title,
            type: v.type,
            severity: v.severity,
            prompt: `Act as a Senior Security Engineer and an Expert Frontend/Backend Developer.

I have run a security audit and identified the following issue in the codebase:

**ISSUE TITLE:** ${v.title}
**SEVERITY:** ${v.severity}
**TYPE:** ${v.type}

**DESCRIPTION:**
${v.description}

**RECOMMENDATION:**
${v.recommendation}

**YOUR TASK:**
1. Analyze the relevant files in the current workspace to locate where this issue exists.
2. Implement the necessary code or configuration changes to fix this vulnerability according to the recommendation.
3. Ensure the fix follows best security practices (OWASP).
4. Explain briefly what you changed and why.

**Constraints:**
- Do not ask me for permission, just fix it.
- If the issue is in a config file (like vercel.json, next.config.js, headers), modify it directly.
- Be precise and provide working code examples.
- Test the changes to ensure they work correctly.

**URL:** ${scanResult.url}
**DOMAIN:** ${scanResult.domain}`
          })) || []
        }

        const blob = new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `security-scan-${scanResult.domain}.json`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      } else if (format === 'csv') {
        const headers = ['Issue', 'Type', 'Severity', 'Description', 'Recommendation', 'AI_Prompt']
        const rows = scanResult.vulnerabilities?.map((v: any) => [
          `"${v.title}"`,
          `"${v.type}"`,
          `"${v.severity}"`,
          `"${v.description}"`,
          `"${v.recommendation}"`,
          `"Act as a Senior Security Engineer and an Expert Frontend/Backend Developer.

I have run a security audit and identified the following issue in the codebase:

**ISSUE TITLE:** ${v.title}
**SEVERITY:** ${v.severity}
**TYPE:** ${v.type}

**DESCRIPTION:**
${v.description}

**RECOMMENDATION:**
${v.recommendation}

**YOUR TASK:**
1. Analyze the relevant files in the current workspace to locate where this issue exists.
2. Implement the necessary code or configuration changes to fix this vulnerability according to the recommendation.
3. Ensure the fix follows best security practices (OWASP).
4. Explain briefly what you changed and why.

**Constraints:**
- Do not ask me for permission, just fix it.
- If the issue is in a config file (like vercel.json, next.config.js, headers), modify it directly.
- Be precise and provide working code examples.
- Test the changes to ensure they work correctly.

**URL:** ${scanResult.url}
**DOMAIN:** ${scanResult.domain}"`
        ]) || []

        const csvContent = [headers.join(','), ...rows.map(row => row.join(','))].join('\n')
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `vulnerabilities-${scanResult.domain}.csv`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Download error:', err)
      setError(t.downloadFailed)
    }
  }

  const startScan = async () => {
    if (!url) {
      setError(t.pleaseEnterUrl)
      return
    }

    try {
      new URL(url.startsWith('http') ? url : `https://${url}`)
    } catch {
      setError(t.invalidUrl)
      return
    }

    setLoading(true)
    setError('')
    setScanResult(null)

    try {
      const targetUrl = url.startsWith('http') ? url : `https://${url}`
      console.log('Starting scan for URL:', targetUrl)
      
      const response = await fetch(`/api/security/scan?url=${encodeURIComponent(targetUrl)}`)
      console.log('Response status:', response.status)
      
      const data = await response.json()
      console.log('Response data:', data)

      if (data.error) {
        setError(data.error)
        if (data.details) {
          setError(data.error + '\n\nDetails: ' + JSON.stringify(data.details, null, 2))
        }
      } else {
        setScanResult(data)
      }
    } catch (err: any) {
      console.error('Scan error details:', err)
      const errorMessage = err.response?.data?.error || err.message || t.scanFailed
      setError(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      startScan()
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-cyan-950 to-purple-950">
      <div className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-12">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="h-14 w-14 text-cyan-400 drop-shadow-[0_0_20px_rgba(34,211,238,0.6)]" />
              <div className="absolute -inset-1 bg-cyan-400 blur-xl opacity-20"></div>
            </div>
            <div>
              <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 drop-shadow-[0_0_10px_rgba(34,211,238,0.5)]">
                {t.appTitle}
              </h1>
              <p className="text-base text-gray-300 max-w-2xl">
                {t.appDescription}
              </p>
            </div>
          </div>
          
          {/* Language Switcher */}
          <Button
            variant="outline"
            size="lg"
            onClick={() => setLanguage(language === 'en' ? 'ru' : 'en')}
            className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/20 hover:border-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.3)] transition-all"
          >
            <Languages className="h-5 w-5 mr-2" />
            {language === 'en' ? 'RU' : 'EN'}
          </Button>
        </div>

        {/* Scan Input */}
        <Card className="mb-8 shadow-2xl border-2 border-cyan-500/30 bg-gray-900/80 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-2xl text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]">
              {t.scanner}
            </CardTitle>
            <CardDescription className="text-gray-300">
              {t.scannerDesc}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-3">
              <Input
                type="text"
                placeholder={t.placeholder}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyPress={handleKeyPress}
                disabled={loading}
                className="flex-1 text-lg h-12 bg-gray-950/80 border-cyan-500/30 text-white placeholder:text-gray-500 focus:border-cyan-400 focus:ring-cyan-400/20"
              />
              <Button
                onClick={startScan}
                disabled={loading}
                size="lg"
                className="h-12 px-8 bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-semibold shadow-[0_0_20px_rgba(34,211,238,0.4)] hover:shadow-[0_0_25px_rgba(168,85,247,0.5)] transition-all"
              >
                {loading ? (
                  <>
                    <Clock className="mr-2 h-5 w-5 animate-spin text-cyan-400" />
                    {t.scanning}
                  </>
                ) : (
                  <>
                    <Shield className="mr-2 h-5 w-5" />
                    {t.checkSecurity}
                  </>
                )}
              </Button>
            </div>
            {error && (
              <div className="mt-4 p-4 bg-red-500/20 border border-red-500/50 rounded-lg">
                <p className="text-red-300 font-medium flex items-center gap-2">
                  <XCircle className="h-5 w-5" />
                  {error}
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Scan Results */}
        {scanResult && (
          <div className="space-y-6">
            {/* Overall Score Card */}
            <Card className="shadow-2xl border-2 border-cyan-500/30 bg-gray-900/80 backdrop-blur-sm">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-2xl text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]">
                      {t.securityResults}
                    </CardTitle>
                    <CardDescription className="text-gray-300">
                      {t.target}: <span className="font-semibold text-cyan-300">{scanResult.url}</span>
                    </CardDescription>
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-2 mb-1">
                      {getRiskIcon(scanResult.riskLevel)}
                      <Badge className={getSeverityColor(scanResult.riskLevel)}>
                        {t[scanResult.riskLevel.toLowerCase() as keyof typeof t]}
                      </Badge>
                    </div>
                    <div className={`text-5xl font-bold ${getScoreColor(scanResult.overallScore)}`}>
                      {scanResult.overallScore}{t.scoreOutOf100}
                    </div>
                    <div className="text-sm text-cyan-400">{t.securityScore}</div>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm" className="ml-4 border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/20">
                        <Download className="h-4 w-4 mr-2" />
                        {t.export}
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="bg-gray-900 border border-cyan-500/30">
                      <DropdownMenuItem onClick={handleDownloadMarkdown} className="text-gray-200 hover:bg-cyan-500/20">
                        <FileText className="h-4 w-4 mr-2 text-cyan-400" />
                        {t.markdownReport}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={handleDownloadJSON} className="text-gray-200 hover:bg-cyan-500/20">
                        <Database className="h-4 w-4 mr-2 text-cyan-400" />
                        {t.jsonExport}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={handleDownloadCSV} className="text-gray-200 hover:bg-cyan-500/20">
                        <Download className="h-4 w-4 mr-2 text-cyan-400" />
                        {t.csvExport}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </CardHeader>
              <CardContent>
                <Progress value={scanResult.overallScore} className="h-3 bg-gray-800" />
              </CardContent>
            </Card>

            {/* Detailed Results Tabs */}
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="grid w-full grid-cols-6 bg-gray-900/80 border border-cyan-500/30">
                <TabsTrigger value="overview" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400 text-gray-300 hover:bg-cyan-500/10">
                  {t.overview}
                </TabsTrigger>
                <TabsTrigger value="ssl" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400 text-gray-300 hover:bg-cyan-500/10">
                  {t.ssl}
                </TabsTrigger>
                <TabsTrigger value="headers" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400 text-gray-300 hover:bg-cyan-500/10">
                  {t.headers}
                </TabsTrigger>
                <TabsTrigger value="dns" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400 text-gray-300 hover:bg-cyan-500/10">
                  {t.dns}
                </TabsTrigger>
                <TabsTrigger value="performance" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400 text-gray-300 hover:bg-cyan-500/10">
                  {t.performance}
                </TabsTrigger>
                <TabsTrigger value="vulnerabilities" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400 text-gray-300 hover:bg-cyan-500/10">
                  {t.vulnerabilities}
                </TabsTrigger>
              </TabsList>

              {/* Overview Tab */}
              <TabsContent value="overview" className="space-y-4">
                <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <Card className="shadow-lg border-2 border-cyan-500/30 bg-gray-900/80 hover:border-cyan-500/50 transition-all hover:shadow-[0_0_20px_rgba(34,211,238,0.3)]">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2 text-cyan-400">
                        <Lock className="h-4 w-4" />
                        {t.sslTls}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.sslCheck?.score || 0)}`}>
                        {scanResult.sslCheck?.score || 0}{t.scoreOutOf100}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="shadow-lg border-2 border-purple-500/30 bg-gray-900/80 hover:border-purple-500/50 transition-all hover:shadow-[0_0_20px_rgba(168,85,247,0.3)]">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2 text-purple-400">
                        <Server className="h-4 w-4" />
                        {t.securityHeaders}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.headersCheck?.score || 0)}`}>
                        {scanResult.headersCheck?.score || 0}{t.scoreOutOf100}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="shadow-lg border-2 border-green-500/30 bg-gray-900/80 hover:border-green-500/50 transition-all hover:shadow-[0_0_20px_rgba(34,197,94,0.3)]">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2 text-green-400">
                        <Globe className="h-4 w-4" />
                        {t.dnsSecurity}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.dnsCheck?.score || 0)}`}>
                        {scanResult.dnsCheck?.score || 0}{t.scoreOutOf100}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="shadow-lg border-2 border-yellow-500/30 bg-gray-900/80 hover:border-yellow-500/50 transition-all hover:shadow-[0_0_20px_rgba(234,179,8,0.3)]">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2 text-yellow-400">
                        <Zap className="h-4 w-4" />
                        {t.performance}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.performance?.score || 0)}`}>
                        {scanResult.performance?.score || 0}{t.scoreOutOf100}
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Vulnerability Summary */}
                {scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0 && (
                  <Card className="shadow-lg border-2 border-red-500/30 bg-gray-900/80">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]">
                        <Bug className="h-5 w-5" />
                        {t.vulnerabilitiesFound}: {scanResult.vulnerabilities.length}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-96 pr-4">
                        <div className="space-y-3">
                          {scanResult.vulnerabilities.map((vuln, index) => (
                            <Card key={index} className="border-2 border-red-500/30 bg-gray-950/80">
                              <CardContent className="pt-4">
                                <div className="flex items-start justify-between gap-4">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                      <Badge className={getSeverityColor(vuln.severity)}>
                                        {t[vuln.severity.toLowerCase() as keyof typeof t]}
                                      </Badge>
                                      <Badge variant="outline" className="border-cyan-500/50 text-cyan-400">
                                        {vuln.type}
                                      </Badge>
                                    </div>
                                    <h4 className="font-semibold text-lg mb-2 text-gray-100">{vuln.title}</h4>
                                    <p className="text-sm text-gray-400 mb-3">
                                      {vuln.description}
                                    </p>
                                    <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                      <p className="text-sm font-medium text-cyan-300 flex items-start gap-2">
                                        <CheckCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                                        {t.recommendation}: {vuln.recommendation}
                                      </p>
                                    </div>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* SSL/TLS Tab */}
              <TabsContent value="ssl">
                {scanResult.sslCheck && (
                  <Card className="shadow-lg border-2 border-cyan-500/30 bg-gray-900/80">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]">
                        <Lock className="h-5 w-5" />
                        {t.sslCertificate}
                      </CardTitle>
                      <CardDescription className="text-gray-300">
                        {t.headersScore}: <span className="font-semibold text-cyan-300">{scanResult.sslCheck.score}{t.scoreOutOf100}</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <label className="text-sm font-medium text-gray-300">{t.certificatePresent}</label>
                          <div className="flex items-center gap-2">
                            {scanResult.sslCheck.hasCertificate ? (
                              <CheckCircle className="h-5 w-5 text-green-400 drop-shadow-[0_0_8px_rgba(34,197,94,0.6)]" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
                            )}
                            <span className="font-semibold text-gray-100">
                              {scanResult.sslCheck.hasCertificate ? t.yes : t.no}
                            </span>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <label className="text-sm font-medium text-gray-300">{t.certificateValid}</label>
                          <div className="flex items-center gap-2">
                            {scanResult.sslCheck.isValid ? (
                              <CheckCircle className="h-5 w-5 text-green-400 drop-shadow-[0_0_8px_rgba(34,197,94,0.6)]" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
                            )}
                            <span className="font-semibold text-gray-100">
                              {scanResult.sslCheck.isValid ? t.yes : t.no}
                            </span>
                          </div>
                        </div>

                        {scanResult.sslCheck.issuer && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium text-gray-300">{t.issuer}</label>
                            <p className="text-sm text-gray-400">{scanResult.sslCheck.issuer}</p>
                          </div>
                        )}

                        {scanResult.sslCheck.tlsVersion && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium text-gray-300">{t.tlsVersion}</label>
                            <Badge variant="outline" className="text-sm border-cyan-500/50 text-cyan-400">
                              {scanResult.sslCheck.tlsVersion}
                            </Badge>
                          </div>
                        )}

                        {scanResult.sslCheck.validFrom && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium text-gray-300">{t.validFrom}</label>
                            <p className="text-sm text-gray-400">
                              {new Date(scanResult.sslCheck.validFrom).toLocaleDateString()}
                            </p>
                          </div>
                        )}

                        {scanResult.sslCheck.validTo && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium text-gray-300">{t.validTo}</label>
                            <p className="text-sm text-gray-400">
                              {new Date(scanResult.sslCheck.validTo).toLocaleDateString()}
                            </p>
                          </div>
                        )}

                        {scanResult.sslCheck.daysUntilExpiry !== undefined && (
                          <div className="space-y-2 md:col-span-2">
                            <label className="text-sm font-medium text-gray-300">{t.daysUntilExpiry}</label>
                            <div className="flex items-center gap-2">
                              <Clock className="h-5 w-5 text-cyan-400" />
                              <span className="text-lg font-semibold text-gray-100">
                                {scanResult.sslCheck.daysUntilExpiry} {t.days}
                              </span>
                              {scanResult.sslCheck.daysUntilExpiry < 30 && (
                                <Badge className="bg-red-600 text-white shadow-[0_0_10px_rgba(239,68,68,0.5)] ml-2">
                                  ⚠️ {t.expiringSoon}
                                </Badge>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* Security Headers Tab */}
              <TabsContent value="headers">
                {scanResult.headersCheck && (
                  <Card className="shadow-lg border-2 border-purple-500/30 bg-gray-900/80">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-purple-400 drop-shadow-[0_0_5px_rgba(168,85,247,0.5)]">
                        <Server className="h-5 w-5" />
                        {t.securityHeadersAnalysis}
                      </CardTitle>
                      <CardDescription className="text-gray-300">
                        {t.headersScore}: <span className="font-semibold text-purple-300">{scanResult.headersCheck.score}{t.scoreOutOf100}</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid md:grid-cols-2 gap-4">
                        {[
                          { key: 'hasCSP', label: 'Content-Security-Policy (CSP)', icon: <Shield className="h-4 w-4" /> },
                          { key: 'hasHSTS', label: 'HTTP Strict Transport Security (HSTS)', icon: <Lock className="h-4 w-4" /> },
                          { key: 'hasXFrameOptions', label: 'X-Frame-Options', icon: <Shield className="h-4 w-4" /> },
                          { key: 'hasXSSProtection', label: 'X-XSS-Protection', icon: <Bug className="h-4 w-4" /> },
                        ].map((header) => (
                          <Card key={header.key} className="border-2 border-purple-500/30 bg-gray-950/80 hover:border-purple-500/50 transition-all">
                            <CardContent className="pt-4">
                              <div className="flex items-center justify-between gap-4">
                                <div className="flex items-center gap-2">
                                  {header.icon}
                                  <span className="font-medium text-gray-200">{header.label}</span>
                                </div>
                                {scanResult.headersCheck[header.key as keyof typeof scanResult.headersCheck] ? (
                                  <CheckCircle className="h-5 w-5 text-green-400 drop-shadow-[0_0_8px_rgba(34,197,94,0.6)] flex-shrink-0" />
                                ) : (
                                  <XCircle className="h-5 w-5 text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.6)] flex-shrink-0" />
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>

                      {scanResult.headersCheck.missingHeaders && scanResult.headersCheck.missingHeaders.length > 0 && (
                        <div className="mt-6 p-4 bg-yellow-500/20 border border-yellow-500/50 rounded-lg">
                          <h4 className="font-semibold text-yellow-300 mb-2 flex items-center gap-2">
                            <AlertTriangle className="h-5 w-5" />
                            {t.missingHeaders}
                          </h4>
                          <ul className="list-disc list-inside space-y-1">
                            {scanResult.headersCheck.missingHeaders.map((header, index) => (
                              <li key={index} className="text-sm text-yellow-200">
                                {header}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Detailed Recommendations - Only show for missing headers */}
                      {(!scanResult.headersCheck.hasCSP || !scanResult.headersCheck.hasHSTS || !scanResult.headersCheck.hasXFrameOptions) && (
                        <div className="mt-6 space-y-4">
                          <h3 className="text-lg font-semibold text-purple-300 mb-4 flex items-center gap-2">
                            <Info className="h-5 w-5" />
                            {language === 'ru' ? 'Детальные рекомендации по заголовкам безопасности' : 'Detailed Security Header Recommendations'}
                          </h3>

                          {/* CSP - Show only if missing */}
                          {!scanResult.headersCheck.hasCSP && (
                            <Card className="border-2 border-cyan-500/30 bg-gray-950/80">
                              <CardContent className="pt-6 space-y-4">
                                <h4 className="text-cyan-400 font-semibold text-lg mb-2">{t.cspTitle}</h4>
                                
                                <div className="space-y-3">
                                  <div className="p-3 bg-gray-900 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whatIs}</p>
                                    <p className="text-sm text-gray-400">{t.cspDesc}</p>
                                  </div>

                                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-green-300 mb-1">{t.whatFor}</p>
                                    <p className="text-sm text-green-200">{t.cspPurpose}</p>
                                  </div>

                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1">{t.risks}</p>
                                    <p className="text-sm text-red-200">{t.cspRisks}</p>
                                  </div>

                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1">{t.recommendation}</p>
                                    <p className="text-sm text-cyan-200">{t.cspRecommendation}</p>
                                  </div>

                                  <div className="p-3 bg-purple-500/20 border border-purple-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-purple-300 mb-1">{t.codeExample}</p>
                                    <pre className="bg-gray-950 p-3 rounded overflow-x-auto mt-2">
                                      <code className="text-sm text-green-400">{t.cspCode}</code>
                                    </pre>
                                  </div>

                                  <div className="p-3 bg-gray-900/80 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whereToConfigure}</p>
                                    <p className="text-sm text-gray-400">{t.cspHowTo}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          )}

                          {/* HSTS - Show only if missing */}
                          {!scanResult.headersCheck.hasHSTS && (
                            <Card className="border-2 border-cyan-500/30 bg-gray-950/80">
                              <CardContent className="pt-6 space-y-4">
                                <h4 className="text-cyan-400 font-semibold text-lg mb-2">{t.hstsTitle}</h4>
                                
                                <div className="space-y-3">
                                  <div className="p-3 bg-gray-900 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whatIs}</p>
                                    <p className="text-sm text-gray-400">{t.hstsDesc}</p>
                                  </div>

                                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-green-300 mb-1">{t.whatFor}</p>
                                    <p className="text-sm text-green-200">{t.hstsPurpose}</p>
                                  </div>

                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1">{t.risks}</p>
                                    <p className="text-sm text-red-200">{t.hstsRisks}</p>
                                  </div>

                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1">{t.recommendation}</p>
                                    <p className="text-sm text-cyan-200">{t.hstsRecommendation}</p>
                                  </div>

                                  <div className="p-3 bg-purple-500/20 border border-purple-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-purple-300 mb-1">{t.codeExample}</p>
                                    <pre className="bg-gray-950 p-3 rounded overflow-x-auto mt-2">
                                      <code className="text-sm text-green-400">{t.hstsCode}</code>
                                    </pre>
                                  </div>

                                  <div className="p-3 bg-gray-900/80 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whereToConfigure}</p>
                                    <p className="text-sm text-gray-400">{t.hstsHowTo}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          )}

                          {/* X-Frame-Options - Show only if missing */}
                          {!scanResult.headersCheck.hasXFrameOptions && (
                            <Card className="border-2 border-cyan-500/30 bg-gray-950/80">
                              <CardContent className="pt-6 space-y-4">
                                <h4 className="text-cyan-400 font-semibold text-lg mb-2">{t.xFrameTitle}</h4>
                                
                                <div className="space-y-3">
                                  <div className="p-3 bg-gray-900 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whatIs}</p>
                                    <p className="text-sm text-gray-400">{t.xFrameDesc}</p>
                                  </div>

                                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-green-300 mb-1">{t.whatFor}</p>
                                    <p className="text-sm text-green-200">{t.xFramePurpose}</p>
                                  </div>

                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1">{t.risks}</p>
                                    <p className="text-sm text-red-200">{t.xFrameRisks}</p>
                                  </div>

                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1">{t.recommendation}</p>
                                    <p className="text-sm text-cyan-200">{t.xFrameRecommendation}</p>
                                  </div>

                                  <div className="p-3 bg-purple-500/20 border border-purple-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-purple-300 mb-1">{t.codeExample}</p>
                                    <pre className="bg-gray-950 p-3 rounded overflow-x-auto mt-2">
                                      <code className="text-sm text-green-400">{t.xFrameCode}</code>
                                    </pre>
                                  </div>

                                  <div className="p-3 bg-gray-900/80 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whereToConfigure}</p>
                                    <p className="text-sm text-gray-400">{t.xFrameHowTo}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          )}
                        </div>
                      )}

                      {/* No Issues Message */}
                      {scanResult.headersCheck.hasCSP && scanResult.headersCheck.hasHSTS && scanResult.headersCheck.hasXFrameOptions && (
                        <div className="mt-6 p-4 bg-green-500/20 border border-green-500/50 rounded-lg">
                          <div className="flex items-center gap-2">
                            <CheckCircle className="h-5 w-5 text-green-400" />
                            <p className="text-green-300 font-medium">
                              {language === 'ru' ? 'Все проверенные заголовки безопасности настроены правильно! Рекомендации не требуются.' : 'All security headers configured correctly! No recommendations needed.'}
                            </p>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* DNS Tab */}
              <TabsContent value="dns">
                {scanResult.dnsCheck && (
                  <Card className="shadow-lg border-2 border-green-500/30 bg-gray-900/80">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-green-400 drop-shadow-[0_0_5px_rgba(34,197,94,0.5)]">
                        <Globe className="h-5 w-5" />
                        {t.dnsSecurityConfig}
                      </CardTitle>
                      <CardDescription className="text-gray-300">
                        {t.headersScore}: <span className="font-semibold text-green-300">{scanResult.dnsCheck.score}{t.scoreOutOf100}</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid md:grid-cols-2 gap-4">
                        {[
                          { key: 'hasDNSSEC', label: t.dnssecTitle, icon: <Lock className="h-4 w-4" /> },
                          ...(scanResult.dnsCheck.hasMXRecord ? [
                            { key: 'hasSPF', label: t.spfTitle, icon: <Mail className="h-4 w-4" /> },
                            { key: 'hasDMARC', label: t.dmarcTitle, icon: <Shield className="h-4 w-4" /> },
                            { key: 'hasDKIM', label: t.dkimTitle, icon: <Key className="h-4 w-4" /> },
                          ] : []),
                        ].map((check) => (
                          <Card key={check.key} className="border-2 border-green-500/30 bg-gray-950/80 hover:border-green-500/50 transition-all">
                            <CardContent className="pt-4">
                              <div className="flex items-center justify-between gap-4">
                                <div className="flex items-center gap-2">
                                  {check.icon}
                                  <span className="font-medium text-gray-200">{check.label}</span>
                                </div>
                                {scanResult.dnsCheck[check.key as keyof typeof scanResult.dnsCheck] ? (
                                  <CheckCircle className="h-5 w-5 text-green-400 drop-shadow-[0_0_8px_rgba(34,197,94,0.6)] flex-shrink-0" />
                                ) : (
                                  <XCircle className="h-5 w-5 text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.6)] flex-shrink-0" />
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>

                      {/* Detailed DNS Recommendations - Only show if there are problems */}
                      {(scanResult.dnsCheck.hasMXRecord && (!scanResult.dnsCheck.hasSPF || !scanResult.dnsCheck.hasDMARC || !scanResult.dnsCheck.hasDKIM) || !scanResult.dnsCheck.hasDNSSEC) && (
                        <div className="mt-6 space-y-4">
                          <h3 className="text-lg font-semibold text-green-300 mb-4 flex items-center gap-2">
                            <Info className="h-5 w-5" />
                            {language === 'ru' ? 'Детальные рекомендации по DNS безопасности' : 'Detailed DNS Security Recommendations'}
                          </h3>

                          {/* SPF - Show only if MX exists and SPF is missing */}
                          {scanResult.dnsCheck.hasMXRecord && !scanResult.dnsCheck.hasSPF && (
                            <Card className="border-2 border-cyan-500/30 bg-gray-950/80">
                              <CardContent className="pt-6 space-y-4">
                                <h4 className="text-cyan-400 font-semibold text-lg mb-2 flex items-center gap-2">
                                  <Mail className="h-5 w-5" />
                                  {t.spfTitle}
                                </h4>
                                
                                <div className="space-y-3">
                                  <div className="p-3 bg-gray-900 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whatIs}</p>
                                    <p className="text-sm text-gray-400">{t.spfDesc}</p>
                                  </div>

                                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-green-300 mb-1">{t.whatFor}</p>
                                    <p className="text-sm text-green-200">{t.spfPurpose}</p>
                                  </div>

                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1">{t.risks}</p>
                                    <p className="text-sm text-red-200">{t.spfRisks}</p>
                                  </div>

                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1">{t.recommendation}</p>
                                    <p className="text-sm text-cyan-200">{t.spfRecommendation}</p>
                                  </div>

                                  <div className="p-3 bg-gray-900/80 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whereToConfigure}</p>
                                    <p className="text-sm text-gray-400">{t.spfWhere}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          )}

                          {/* DMARC - Show only if MX exists and DMARC is missing */}
                          {scanResult.dnsCheck.hasMXRecord && !scanResult.dnsCheck.hasDMARC && (
                            <Card className="border-2 border-cyan-500/30 bg-gray-950/80">
                              <CardContent className="pt-6 space-y-4">
                                <h4 className="text-cyan-400 font-semibold text-lg mb-2 flex items-center gap-2">
                                  <Shield className="h-5 w-5" />
                                  {t.dmarcTitle}
                                </h4>
                                
                                <div className="space-y-3">
                                  <div className="p-3 bg-gray-900 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whatIs}</p>
                                    <p className="text-sm text-gray-400">{t.dmarcDesc}</p>
                                  </div>

                                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-green-300 mb-1">{t.whatFor}</p>
                                    <p className="text-sm text-green-200">{t.dmarcPurpose}</p>
                                  </div>

                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1">{t.risks}</p>
                                    <p className="text-sm text-red-200">{t.dmarcRisks}</p>
                                  </div>

                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1">{t.recommendation}</p>
                                    <p className="text-sm text-cyan-200">{t.dmarcRecommendation}</p>
                                  </div>

                                  <div className="p-3 bg-gray-900/80 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whereToConfigure}</p>
                                    <p className="text-sm text-gray-400">{t.dmarcWhere}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          )}

                          {/* DKIM - Show only if MX exists and DKIM is missing */}
                          {scanResult.dnsCheck.hasMXRecord && !scanResult.dnsCheck.hasDKIM && (
                            <Card className="border-2 border-cyan-500/30 bg-gray-950/80">
                              <CardContent className="pt-6 space-y-4">
                                <h4 className="text-cyan-400 font-semibold text-lg mb-2 flex items-center gap-2">
                                  <Key className="h-5 w-5" />
                                  {t.dkimTitle}
                                </h4>
                                
                                <div className="space-y-3">
                                  <div className="p-3 bg-gray-900 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whatIs}</p>
                                    <p className="text-sm text-gray-400">{t.dkimDesc}</p>
                                  </div>

                                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-green-300 mb-1">{t.whatFor}</p>
                                    <p className="text-sm text-green-200">{t.dkimPurpose}</p>
                                  </div>

                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1">{t.risks}</p>
                                    <p className="text-sm text-red-200">{t.dkimRisks}</p>
                                  </div>

                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1">{t.recommendation}</p>
                                    <p className="text-sm text-cyan-200">{t.dkimRecommendation}</p>
                                  </div>

                                  <div className="p-3 bg-gray-900/80 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whereToConfigure}</p>
                                    <p className="text-sm text-gray-400">{t.dkimWhere}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          )}

                          {/* DNSSEC - Show only if DNSSEC is missing */}
                          {!scanResult.dnsCheck.hasDNSSEC && (
                            <Card className="border-2 border-cyan-500/30 bg-gray-950/80">
                              <CardContent className="pt-6 space-y-4">
                                <h4 className="text-cyan-400 font-semibold text-lg mb-2 flex items-center gap-2">
                                  <Lock className="h-5 w-5" />
                                  {t.dnssecTitle}
                                </h4>
                                
                                <div className="space-y-3">
                                  <div className="p-3 bg-gray-900 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whatIs}</p>
                                    <p className="text-sm text-gray-400">{t.dnssecDesc}</p>
                                  </div>

                                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-green-300 mb-1">{t.whatFor}</p>
                                    <p className="text-sm text-green-200">{t.dnssecPurpose}</p>
                                  </div>

                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1">{t.risks}</p>
                                    <p className="text-sm text-red-200">{t.dnssecRisks}</p>
                                  </div>

                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1">{t.recommendation}</p>
                                    <p className="text-sm text-cyan-200">{t.dnssecRecommendation}</p>
                                  </div>

                                  <div className="p-3 bg-gray-900/80 border border-gray-700 rounded-lg">
                                    <p className="text-sm font-medium text-gray-300 mb-1">{t.whereToConfigure}</p>
                                    <p className="text-sm text-gray-400">{t.dnssecWhere}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          )}
                        </div>
                      )}

                      {/* No Issues Message */}
                      {scanResult.dnsCheck.hasMXRecord && scanResult.dnsCheck.hasSPF && scanResult.dnsCheck.hasDMARC && scanResult.dnsCheck.hasDKIM && scanResult.dnsCheck.hasDNSSEC && (
                        <div className="mt-6 p-4 bg-green-500/20 border border-green-500/50 rounded-lg">
                          <div className="flex items-center gap-2">
                            <CheckCircle className="h-5 w-5 text-green-400" />
                            <p className="text-green-300 font-medium">
                              {language === 'ru' ? 'Все DNS проверки пройдены успешно! Рекомендации не требуются.' : 'All DNS checks passed! No recommendations needed.'}
                            </p>
                          </div>
                        </div>
                      )}

                      {!scanResult.dnsCheck.hasMXRecord && scanResult.dnsCheck.hasDNSSEC && (
                        <div className="mt-6 p-4 bg-green-500/20 border border-green-500/50 rounded-lg">
                          <div className="flex items-center gap-2">
                            <CheckCircle className="h-5 w-5 text-green-400" />
                            <p className="text-green-300 font-medium">
                              {language === 'ru' ? 'DNSSEC настроен правильно. Рекомендации по email безопасности не требуются (нет MX записей).' : 'DNSSEC is configured correctly. Email security recommendations not needed (no MX records).'}
                            </p>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* Performance Tab */}
              <TabsContent value="performance">
                {scanResult.performance && (
                  <Card className="shadow-lg border-2 border-yellow-500/30 bg-gray-900/80">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-yellow-400 drop-shadow-[0_0_5px_rgba(234,179,8,0.5)]">
                        <Zap className="h-5 w-5" />
                        {t.performanceAnalysis}
                      </CardTitle>
                      <CardDescription className="text-gray-300">
                        {t.headersScore}: <span className="font-semibold text-yellow-300">{scanResult.performance.score}{t.scoreOutOf100}</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <Card className="border border-yellow-500/30 bg-gray-950/80">
                          <CardHeader className="pb-2">
                            <CardDescription className="text-gray-400">{t.httpStatus}</CardDescription>
                          </CardHeader>
                          <CardContent>
                            <Badge variant={scanResult.performance.statusCode === 200 ? 'default' : 'destructive'} className="bg-cyan-500/20 text-cyan-300 border-cyan-500/30">
                              {scanResult.performance.statusCode}
                            </Badge>
                          </CardContent>
                        </Card>

                        <Card className="border border-yellow-500/30 bg-gray-950/80">
                          <CardHeader className="pb-2">
                            <CardDescription className="text-gray-400">{t.responseTime}</CardDescription>
                          </CardHeader>
                          <CardContent>
                            <div className="text-2xl font-bold text-yellow-300">
                              {scanResult.performance.responseTime}ms
                            </div>
                          </CardContent>
                        </Card>

                        {scanResult.performance.ttfb && (
                          <Card className="border border-yellow-500/30 bg-gray-950/80">
                            <CardHeader className="pb-2">
                              <CardDescription className="text-gray-400">TTFB</CardDescription>
                            </CardHeader>
                            <CardContent>
                              <div className="text-2xl font-bold text-yellow-300">
                                {scanResult.performance.ttfb}ms
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {scanResult.performance.httpVersion && (
                          <Card className="border border-yellow-500/30 bg-gray-950/80">
                            <CardHeader className="pb-2">
                              <CardDescription className="text-gray-400">HTTP Version</CardDescription>
                            </CardHeader>
                            <CardContent>
                              <Badge variant="outline" className="text-sm border-cyan-500/50 text-cyan-400">
                                {scanResult.performance.httpVersion}
                              </Badge>
                            </CardContent>
                          </Card>
                        )}
                      </div>

                      <div className="grid md:grid-cols-2 gap-4">
                        <Card className="border-2 border-yellow-500/30 bg-gray-950/80">
                          <CardContent className="pt-4">
                            <div className="flex items-center justify-between">
                              <span className="font-medium text-gray-200">{t.gzipCompression}</span>
                              {scanResult.performance.hasGzip ? (
                                <CheckCircle className="h-5 w-5 text-green-400 drop-shadow-[0_0_8px_rgba(34,197,94,0.6)]" />
                              ) : (
                                <XCircle className="h-5 w-5 text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
                              )}
                            </div>
                          </CardContent>
                        </Card>

                        {scanResult.performance.httpVersion && (
                          <Card className="border-2 border-yellow-500/30 bg-gray-950/80">
                            <CardContent className="pt-4">
                              <div className="flex items-center justify-between">
                                <span className="font-medium text-gray-200">{t.http2OrHttp3}</span>
                                {['HTTP/2', 'HTTP/3'].includes(scanResult.performance.httpVersion) ? (
                                  <CheckCircle className="h-5 w-5 text-green-400 drop-shadow-[0_0_8px_rgba(34,197,94,0.6)]" />
                                ) : (
                                  <XCircle className="h-5 w-5 text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* Vulnerabilities Tab */}
              <TabsContent value="vulnerabilities">
                {scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0 ? (
                  <Card className="shadow-lg border-2 border-red-500/30 bg-gray-900/80">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2 text-red-400 drop-shadow-[0_0_5px_rgba(239,68,68,0.5)]">
                        <Bug className="h-5 w-5" />
                        {t.detailedReport}
                      </CardTitle>
                      <CardDescription className="text-gray-300">
                        {scanResult.vulnerabilities.length} {language === 'ru' ? 'проблем' : 'issue(s)'} {language === 'ru' ? 'найдено' : 'found'}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[600px] pr-4">
                        <div className="space-y-4">
                          {scanResult.vulnerabilities.map((vuln, index) => (
                            <Card key={index} className="border-2 border-red-500/30 bg-gray-950/80">
                              <CardContent className="pt-4">
                                <div className="flex items-start justify-between gap-4 mb-3">
                                  <div className="flex items-center gap-2">
                                    <Badge className={getSeverityColor(vuln.severity)}>
                                      {t[vuln.severity.toLowerCase() as keyof typeof t]}
                                    </Badge>
                                    <Badge variant="outline" className="border-cyan-500/50 text-cyan-400">
                                      {vuln.type}
                                    </Badge>
                                  </div>
                                </div>
                                <h4 className="font-semibold text-lg mb-2 text-gray-100">{vuln.title}</h4>
                                <p className="text-sm text-gray-400 mb-4">
                                  {vuln.description}
                                </p>
                                
                                {/* Enhanced Recommendation Format */}
                                <div className="space-y-3">
                                  <div className="p-3 bg-red-500/20 border border-red-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-red-300 mb-1 flex items-center gap-2">
                                      <XCircle className="h-4 w-4" />
                                      {t.problem}
                                    </p>
                                    <p className="text-sm text-red-200">{vuln.title}</p>
                                  </div>
                                  
                                  <div className="p-3 bg-cyan-500/20 border border-cyan-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-cyan-300 mb-1 flex items-center gap-2">
                                      <CheckCircle className="h-4 w-4" />
                                      {t.stepsToFix}
                                    </p>
                                    <div className="mt-2 space-y-2 text-cyan-200">
                                      <p className="text-sm">1. {language === 'ru' ? 'Изучите проблему' : 'Study the issue'}</p>
                                      <p className="text-sm">2. {language === 'ru' ? 'Примените рекомендацию ниже' : 'Apply the recommendation below'}</p>
                                      <p className="text-sm">3. {language === 'ru' ? 'Протестируйте изменения' : 'Test the changes'}</p>
                                    </div>
                                  </div>

                                  <div className="p-3 bg-purple-500/20 border border-purple-500/50 rounded-lg">
                                    <p className="text-sm font-medium text-purple-300 mb-1 flex items-center gap-2">
                                      <Database className="h-4 w-4" />
                                      {t.recommendation}
                                    </p>
                                    <p className="text-sm text-purple-200">{vuln.recommendation}</p>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                ) : (
                  <Card className="shadow-lg border-2 border-green-500/30 bg-gray-900/80">
                    <CardContent className="pt-6">
                      <div className="text-center py-12">
                        <CheckCircle className="h-16 w-16 text-green-400 drop-shadow-[0_0_20px_rgba(34,197,94,0.8)] mx-auto mb-4" />
                        <h3 className="text-xl font-semibold mb-2 text-gray-100">{t.noVulnerabilities}</h3>
                        <p className="text-gray-400">{t.noVulnerabilitiesDesc}</p>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>
            </Tabs>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-16 text-center text-sm text-gray-500 pb-4">
          <p>{t.footer}</p>
        </footer>
      </div>
    </div>
  )
}

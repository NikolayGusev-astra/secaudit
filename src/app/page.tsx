'use client'

import { useState } from 'react'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, AlertTriangle, CheckCircle, XCircle, Clock, Server, Globe, Lock, Zap, Eye, Bug, Mail, Key, Download, FileText, Database } from 'lucide-react'
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
    case 'CRITICAL': return 'bg-red-600 text-white'
    case 'HIGH': return 'bg-orange-600 text-white'
    case 'MEDIUM': return 'bg-yellow-600 text-white'
    case 'LOW': return 'bg-green-600 text-white'
    case 'INFO': return 'bg-gray-600 text-white'
    default: return 'bg-gray-400 text-white'
  }
}

const getRiskIcon = (riskLevel: string) => {
  switch (riskLevel) {
    case 'CRITICAL':
    case 'HIGH':
      return <XCircle className="h-5 w-5 text-red-600" />
    case 'MEDIUM':
      return <AlertTriangle className="h-5 w-5 text-yellow-600" />
    case 'LOW':
      return <Clock className="h-5 w-5 text-orange-600" />
    case 'INFO':
      return <Eye className="h-5 w-5 text-gray-600" />
    default:
      return <CheckCircle className="h-5 w-5 text-green-600" />
  }
}

const getScoreColor = (score: number) => {
  if (score >= 80) return 'text-green-600'
  if (score >= 60) return 'text-yellow-600'
  if (score >= 40) return 'text-orange-600'
  return 'text-red-600'
}

export default function SecurityAuditTool() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanResult, setScanResult] = useState<SecurityScan | null>(null)
  const [error, setError] = useState('')

  const downloadReport = async (format: 'md' | 'json' | 'csv') => {
    if (!scanResult) return

    try {
      if (format === 'md') {
        const response = await fetch(`/api/security/report?scanId=${scanResult.id}`)
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `security-report-${scanResult.domain}.md`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      } else {
        const response = await fetch(`/api/security/export?scanId=${scanResult.id}&format=${format}`)
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = format === 'json'
          ? `security-scan-${scanResult.domain}.json`
          : `vulnerabilities-${scanResult.domain}.csv`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Download error:', err)
      setError('Failed to download report. Please try again.')
    }
  }

  const startScan = async () => {
    if (!url) {
      setError('Please enter a URL')
      return
    }

    // Validate URL format
    try {
      new URL(url.startsWith('http') ? url : `https://${url}`)
    } catch {
      setError('Please enter a valid URL')
      return
    }

    setLoading(true)
    setError('')
    setScanResult(null)

    try {
      const targetUrl = url.startsWith('http') ? url : `https://${url}`
      console.log('Starting scan for URL:', targetUrl)
      console.log('Encoded URL:', encodeURIComponent(targetUrl))
      
      const response = await fetch(`/api/security/scan?url=${encodeURIComponent(targetUrl)}`)
      console.log('Response status:', response.status)
      console.log('Response headers:', Object.fromEntries(response.headers.entries()))
      
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
      console.error('Error stack:', err.stack)
      const errorMessage = err.response?.data?.error || err.message || 'Failed to scan website. Please try again.'
      setError(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      startScan()
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-slate-100 to-slate-200 dark:from-slate-950 dark:via-slate-900 dark:to-slate-800">
      <div className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="h-12 w-12 text-slate-900 dark:text-slate-100" />
            <h1 className="text-5xl font-bold text-slate-900 dark:text-slate-100">
              Security Audit for VibeCoders
            </h1>
          </div>
          <p className="text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
            Professional-grade security and performance scanner. Analyze your website for vulnerabilities,
            security misconfigurations, and performance issues.
          </p>
        </div>

        {/* Scan Input */}
        <Card className="mb-8 shadow-xl border-2">
          <CardHeader>
            <CardTitle className="text-2xl">Website Security Scanner</CardTitle>
            <CardDescription>
              Enter a website URL to perform a comprehensive security and performance audit
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-3">
              <Input
                type="text"
                placeholder="example.com or https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyPress={handleKeyPress}
                disabled={loading}
                className="flex-1 text-lg h-12"
              />
              <Button
                onClick={startScan}
                disabled={loading}
                size="lg"
                className="h-12 px-8 bg-slate-900 hover:bg-slate-800 text-white dark:bg-slate-100 dark:hover:bg-slate-200 dark:text-slate-900 font-semibold"
              >
                {loading ? (
                  <>
                    <Clock className="mr-2 h-5 w-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Shield className="mr-2 h-5 w-5" />
                    Check Security
                  </>
                )}
              </Button>
            </div>
            {error && (
              <div className="mt-4 p-4 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-900 rounded-lg">
                <p className="text-red-800 dark:text-red-200 font-medium flex items-center gap-2">
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
            <Card className="shadow-xl border-2">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-2xl">Security Assessment Results</CardTitle>
                    <CardDescription>
                      Target: <span className="font-semibold text-slate-900 dark:text-slate-100">{scanResult.url}</span>
                    </CardDescription>
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-2 mb-1">
                      {getRiskIcon(scanResult.riskLevel)}
                      <Badge className={getSeverityColor(scanResult.riskLevel)}>
                        {scanResult.riskLevel}
                      </Badge>
                    </div>
                    <div className={`text-4xl font-bold ${getScoreColor(scanResult.overallScore)}`}>
                      {scanResult.overallScore}/100
                    </div>
                    <div className="text-sm text-slate-600 dark:text-slate-400">Security Score</div>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm" className="ml-4">
                        <Download className="h-4 w-4 mr-2" />
                        Export
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => downloadReport('md')}>
                        <FileText className="h-4 w-4 mr-2" />
                        Markdown Report
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => downloadReport('json')}>
                        <Database className="h-4 w-4 mr-2" />
                        JSON Export
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => downloadReport('csv')}>
                        <Download className="h-4 w-4 mr-2" />
                        CSV Export
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </CardHeader>
              <CardContent>
                <Progress value={scanResult.overallScore} className="h-3" />
              </CardContent>
            </Card>

            {/* Detailed Results Tabs */}
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="grid w-full grid-cols-6">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="ssl">SSL/TLS</TabsTrigger>
                <TabsTrigger value="headers">Headers</TabsTrigger>
                <TabsTrigger value="dns">DNS</TabsTrigger>
                <TabsTrigger value="performance">Performance</TabsTrigger>
                <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
              </TabsList>

              {/* Overview Tab */}
              <TabsContent value="overview" className="space-y-4">
                <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <Card className="shadow-lg">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <Lock className="h-4 w-4" />
                        SSL/TLS
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.sslCheck?.score || 0)}`}>
                        {scanResult.sslCheck?.score || 0}/100
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="shadow-lg">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <Server className="h-4 w-4" />
                        Security Headers
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.headersCheck?.score || 0)}`}>
                        {scanResult.headersCheck?.score || 0}/100
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="shadow-lg">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <Globe className="h-4 w-4" />
                        DNS Security
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.dnsCheck?.score || 0)}`}>
                        {scanResult.dnsCheck?.score || 0}/100
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="shadow-lg">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <Zap className="h-4 w-4" />
                        Performance
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className={`text-2xl font-bold ${getScoreColor(scanResult.performance?.score || 0)}`}>
                        {scanResult.performance?.score || 0}/100
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Vulnerability Summary */}
                {scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0 && (
                  <Card className="shadow-lg">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Bug className="h-5 w-5 text-red-600" />
                        Vulnerabilities Found: {scanResult.vulnerabilities.length}
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-96 pr-4">
                        <div className="space-y-3">
                          {scanResult.vulnerabilities.map((vuln, index) => (
                            <Card key={index} className="border-2">
                              <CardContent className="pt-4">
                                <div className="flex items-start justify-between gap-4">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                      <Badge className={getSeverityColor(vuln.severity)}>
                                        {vuln.severity}
                                      </Badge>
                                      <Badge variant="outline">{vuln.type}</Badge>
                                    </div>
                                    <h4 className="font-semibold text-lg mb-2">{vuln.title}</h4>
                                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-3">
                                      {vuln.description}
                                    </p>
                                    <div className="p-3 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-900 rounded-lg">
                                      <p className="text-sm font-medium text-green-800 dark:text-green-200">
                                        💡 Recommendation: {vuln.recommendation}
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
                  <Card className="shadow-lg">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Lock className="h-5 w-5" />
                        SSL/TLS Certificate Analysis
                      </CardTitle>
                      <CardDescription>
                        Score: <span className="font-semibold">{scanResult.sslCheck.score}/100</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Certificate Present</label>
                          <div className="flex items-center gap-2">
                            {scanResult.sslCheck.hasCertificate ? (
                              <CheckCircle className="h-5 w-5 text-green-600" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-600" />
                            )}
                            <span className="font-semibold">
                              {scanResult.sslCheck.hasCertificate ? 'Yes' : 'No'}
                            </span>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <label className="text-sm font-medium">Valid Certificate</label>
                          <div className="flex items-center gap-2">
                            {scanResult.sslCheck.isValid ? (
                              <CheckCircle className="h-5 w-5 text-green-600" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-600" />
                            )}
                            <span className="font-semibold">
                              {scanResult.sslCheck.isValid ? 'Yes' : 'No'}
                            </span>
                          </div>
                        </div>

                        {scanResult.sslCheck.issuer && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium">Issuer</label>
                            <p className="text-sm text-slate-600 dark:text-slate-400">{scanResult.sslCheck.issuer}</p>
                          </div>
                        )}

                        {scanResult.sslCheck.tlsVersion && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium">TLS Version</label>
                            <Badge variant="outline" className="text-sm">
                              {scanResult.sslCheck.tlsVersion}
                            </Badge>
                          </div>
                        )}

                        {scanResult.sslCheck.validFrom && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium">Valid From</label>
                            <p className="text-sm text-slate-600 dark:text-slate-400">
                              {new Date(scanResult.sslCheck.validFrom).toLocaleDateString()}
                            </p>
                          </div>
                        )}

                        {scanResult.sslCheck.validTo && (
                          <div className="space-y-2">
                            <label className="text-sm font-medium">Valid To</label>
                            <p className="text-sm text-slate-600 dark:text-slate-400">
                              {new Date(scanResult.sslCheck.validTo).toLocaleDateString()}
                            </p>
                          </div>
                        )}

                        {scanResult.sslCheck.daysUntilExpiry !== undefined && (
                          <div className="space-y-2 md:col-span-2">
                            <label className="text-sm font-medium">Days Until Expiry</label>
                            <div className="flex items-center gap-2">
                              <Clock className="h-5 w-5" />
                              <span className="text-lg font-semibold">
                                {scanResult.sslCheck.daysUntilExpiry} days
                              </span>
                              {scanResult.sslCheck.daysUntilExpiry < 30 && (
                                <Badge className="bg-red-600 text-white ml-2">
                                  ⚠️ Expiring Soon
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
                  <Card className="shadow-lg">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Server className="h-5 w-5" />
                        Security Headers Analysis
                      </CardTitle>
                      <CardDescription>
                        Score: <span className="font-semibold">{scanResult.headersCheck.score}/100</span>
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
                          <Card key={header.key} className="border-2">
                            <CardContent className="pt-4">
                              <div className="flex items-center justify-between gap-4">
                                <div className="flex items-center gap-2">
                                  {header.icon}
                                  <span className="font-medium">{header.label}</span>
                                </div>
                                {scanResult.headersCheck[header.key as keyof typeof scanResult.headersCheck] ? (
                                  <CheckCircle className="h-5 w-5 text-green-600 flex-shrink-0" />
                                ) : (
                                  <XCircle className="h-5 w-5 text-red-600 flex-shrink-0" />
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>

                      {scanResult.headersCheck.missingHeaders && scanResult.headersCheck.missingHeaders.length > 0 && (
                        <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-950 border border-yellow-200 dark:border-yellow-900 rounded-lg">
                          <h4 className="font-semibold text-yellow-800 dark:text-yellow-200 mb-2">
                            ⚠️ Missing Security Headers
                          </h4>
                          <ul className="list-disc list-inside space-y-1">
                            {scanResult.headersCheck.missingHeaders.map((header, index) => (
                              <li key={index} className="text-sm text-yellow-700 dark:text-yellow-300">
                                {header}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* DNS Tab */}
              <TabsContent value="dns">
                {scanResult.dnsCheck && (
                  <Card className="shadow-lg">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Globe className="h-5 w-5" />
                        DNS Security Configuration
                      </CardTitle>
                      <CardDescription>
                        Score: <span className="font-semibold">{scanResult.dnsCheck.score}/100</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid md:grid-cols-2 gap-4">
                        {[
                          { key: 'hasSPF', label: 'SPF (Sender Policy Framework)', icon: <Mail className="h-4 w-4" /> },
                          { key: 'hasDMARC', label: 'DMARC (Domain-based Message Authentication)', icon: <Shield className="h-4 w-4" /> },
                          { key: 'hasDKIM', label: 'DKIM (DomainKeys Identified Mail)', icon: <Key className="h-4 w-4" /> },
                          { key: 'hasDNSSEC', label: 'DNSSEC (DNS Security Extensions)', icon: <Lock className="h-4 w-4" /> },
                        ].map((check) => (
                          <Card key={check.key} className="border-2">
                            <CardContent className="pt-4">
                              <div className="flex items-center justify-between gap-4">
                                <div className="flex items-center gap-2">
                                  {check.icon}
                                  <span className="font-medium">{check.label}</span>
                                </div>
                                {scanResult.dnsCheck[check.key as keyof typeof scanResult.dnsCheck] ? (
                                  <CheckCircle className="h-5 w-5 text-green-600 flex-shrink-0" />
                                ) : (
                                  <XCircle className="h-5 w-5 text-red-600 flex-shrink-0" />
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>

              {/* Performance Tab */}
              <TabsContent value="performance">
                {scanResult.performance && (
                  <Card className="shadow-lg">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Zap className="h-5 w-5" />
                        Performance Analysis
                      </CardTitle>
                      <CardDescription>
                        Score: <span className="font-semibold">{scanResult.performance.score}/100</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <Card>
                          <CardHeader className="pb-2">
                            <CardDescription>HTTP Status</CardDescription>
                          </CardHeader>
                          <CardContent>
                            <Badge variant={scanResult.performance.statusCode === 200 ? 'default' : 'destructive'}>
                              {scanResult.performance.statusCode}
                            </Badge>
                          </CardContent>
                        </Card>

                        <Card>
                          <CardHeader className="pb-2">
                            <CardDescription>Response Time</CardDescription>
                          </CardHeader>
                          <CardContent>
                            <div className="text-2xl font-bold">
                              {scanResult.performance.responseTime}ms
                            </div>
                          </CardContent>
                        </Card>

                        {scanResult.performance.ttfb && (
                          <Card>
                            <CardHeader className="pb-2">
                              <CardDescription>TTFB</CardDescription>
                            </CardHeader>
                            <CardContent>
                              <div className="text-2xl font-bold">
                                {scanResult.performance.ttfb}ms
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {scanResult.performance.httpVersion && (
                          <Card>
                            <CardHeader className="pb-2">
                              <CardDescription>HTTP Version</CardDescription>
                            </CardHeader>
                            <CardContent>
                              <Badge variant="outline" className="text-sm">
                                {scanResult.performance.httpVersion}
                              </Badge>
                            </CardContent>
                          </Card>
                        )}
                      </div>

                      <div className="grid md:grid-cols-2 gap-4">
                        <Card className="border-2">
                          <CardContent className="pt-4">
                            <div className="flex items-center justify-between">
                              <span className="font-medium">GZIP Compression</span>
                              {scanResult.performance.hasGzip ? (
                                <CheckCircle className="h-5 w-5 text-green-600" />
                              ) : (
                                <XCircle className="h-5 w-5 text-red-600" />
                              )}
                            </div>
                          </CardContent>
                        </Card>

                        {scanResult.performance.httpVersion && (
                          <Card className="border-2">
                            <CardContent className="pt-4">
                              <div className="flex items-center justify-between">
                                <span className="font-medium">HTTP/2 or HTTP/3</span>
                                {['HTTP/2', 'HTTP/3'].includes(scanResult.performance.httpVersion) ? (
                                  <CheckCircle className="h-5 w-5 text-green-600" />
                                ) : (
                                  <XCircle className="h-5 w-5 text-red-600" />
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
                  <Card className="shadow-lg">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Bug className="h-5 w-5 text-red-600" />
                        Detailed Vulnerability Report
                      </CardTitle>
                      <CardDescription>
                        {scanResult.vulnerabilities.length} issue(s) found
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[600px] pr-4">
                        <div className="space-y-4">
                          {scanResult.vulnerabilities.map((vuln, index) => (
                            <Card key={index} className="border-2 border-red-200 dark:border-red-900">
                              <CardContent className="pt-4">
                                <div className="flex items-start justify-between gap-4 mb-3">
                                  <div className="flex items-center gap-2">
                                    <Badge className={getSeverityColor(vuln.severity)}>
                                      {vuln.severity}
                                    </Badge>
                                    <Badge variant="outline">{vuln.type}</Badge>
                                  </div>
                                </div>
                                <h4 className="font-semibold text-lg mb-2">{vuln.title}</h4>
                                <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
                                  {vuln.description}
                                </p>
                                <div className="p-3 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-900 rounded-lg">
                                  <p className="text-sm font-medium text-green-800 dark:text-green-200">
                                    💡 {vuln.recommendation}
                                  </p>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                ) : (
                  <Card className="shadow-lg">
                    <CardContent className="pt-6">
                      <div className="text-center py-12">
                        <CheckCircle className="h-16 w-16 text-green-600 mx-auto mb-4" />
                        <h3 className="text-xl font-semibold mb-2">No Vulnerabilities Found</h3>
                        <p className="text-slate-600 dark:text-slate-400">
                          Great job! Your website passed all security checks.
                        </p>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>
            </Tabs>
          </div>
        )}

        {/* Footer */}
        <footer className="mt-16 text-center text-sm text-slate-600 dark:text-slate-400 pb-4">
          <p>Professional Security Audit Tool • Scan your websites for vulnerabilities and performance issues</p>
        </footer>
      </div>
    </div>
  )
}
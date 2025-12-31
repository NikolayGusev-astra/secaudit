import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

function generateCSV(vulnerabilities: any[]) {
  const headers = ['Type', 'Severity', 'Title', 'Description', 'Recommendation', 'OWASP Category']
  const rows = vulnerabilities.map(v => [
    v.type,
    v.severity,
    `"${(v.title || '').replace(/"/g, '""')}"`,
    `"${(v.description || '').replace(/"/g, '""')}"`,
    `"${(v.recommendation || v.recommendation || '').replace(/"/g, '""')}"`,
    v.owaspCategory || '',
  ])

  return [
    headers.join('\t'),
    ...rows.map(row => row.join('\t'))
  ].join('\n')
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const scanId = searchParams.get('scanId')
  const format = searchParams.get('format') || 'json'

  if (!scanId) {
    return NextResponse.json(
      { error: 'scanId parameter is required' },
      { status: 400 }
    )
  }

  try {
    // Try to get scan from database first
    let scan = null
    let databaseError = false

    try {
      scan = await db.securityScan.findUnique({
        where: { id: scanId },
        include: {
          sslCheck: true,
          headersCheck: true,
          dnsCheck: true,
          performance: true,
          vulnerabilities: true,
          portScans: true,
        },
      })
    } catch (dbError) {
      console.error('Database retrieval failed, export unavailable:', dbError)
      databaseError = true
    }

    if (!scan) {
      if (databaseError) {
        return NextResponse.json(
          {
            error: 'Export unavailable',
            details: 'Database not configured. Export can only be performed when database is available.'
          },
          { status: 503 }
        )
      }
      return NextResponse.json(
        { error: 'Scan not found' },
        { status: 404 }
      )
    }

    const data = {
      scan: {
        id: scan.id,
        url: scan.url,
        domain: scan.domain,
        status: scan.status,
        overallScore: scan.overallScore,
        riskLevel: scan.riskLevel,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
      },
      sslCheck: scan.sslCheck ? {
        ...scan.sslCheck,
        issues: scan.sslCheck.issues ? JSON.parse(scan.sslCheck.issues) : [],
      } : null,
      headersCheck: scan.headersCheck ? {
        ...scan.headersCheck,
        missingHeaders: scan.headersCheck.missingHeaders ? JSON.parse(scan.headersCheck.missingHeaders) : [],
        issues: scan.headersCheck.issues ? JSON.parse(scan.headersCheck.issues) : [],
      } : null,
      dnsCheck: scan.dnsCheck ? {
        ...scan.dnsCheck,
        dnsRecords: scan.dnsCheck.dnsRecords ? JSON.parse(scan.dnsCheck.dnsRecords) : [],
        issues: scan.dnsCheck.issues ? JSON.parse(scan.dnsCheck.issues) : [],
      } : null,
      performance: scan.performance ? {
        ...scan.performance,
        recommendations: scan.performance.recommendations ? JSON.parse(scan.performance.recommendations) : [],
      } : null,
      vulnerabilities: scan.vulnerabilities.map((vuln) => ({
        ...vuln,
        evidence: vuln.evidence ? JSON.parse(vuln.evidence) : undefined,
      })),
      portScans: scan.portScans,
    }

    if (format === 'csv') {
      const csv = generateCSV(data.vulnerabilities)
      const filename = `vulnerabilities-${scan.domain}-${new Date().toISOString().split('T')[0]}.csv`

      return new NextResponse(csv, {
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="${filename}"`,
        },
      })
    }

    // Default to JSON
    const filename = `security-scan-${scan.domain}-${new Date().toISOString().split('T')[0]}.json`
    return new NextResponse(JSON.stringify(data, null, 2), {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
      },
    })
  } catch (error) {
    console.error('Export error:', error)
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    return NextResponse.json(
      { error: 'Failed to export data', details: errorMessage },
      { status: 500 }
    )
  }
}
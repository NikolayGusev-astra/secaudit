import { NextRequest, NextResponse } from 'next/server'
import { enrichSecurityReport, generateAIPromptsForReport } from '@/lib/security-report-enricher'

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const reportData = searchParams.get('report')

  if (!reportData) {
    return NextResponse.json(
      { error: 'Report data is required' },
      { status: 400 }
    )
  }

  try {
    console.log('Generating security report with AI prompts...')

    // Parse the raw markdown report
    const parsedReport = JSON.parse(reportData as string)

    // Auto-detect technology stack from report content
    const techStack = autoDetectStack(parsedReport)
    console.log('Detected tech stack:', techStack)

    // Generate AI-enriched prompts based on detected stack
    const enrichedData = enrichSecurityReport(reportData as string, techStack)

    console.log('Generated enriched prompts:', enrichedData.enrichedPrompts.length)

    return NextResponse.json({
      success: true,
      message: 'Security report enriched successfully',
      data: {
        summary: enrichedData.summary,
        enrichedPrompts: enrichedData.enrichedPrompts,
        actionBreakdown: enrichedData.actionBreakdown,
        detectedStack: techStack,
      }
    })
  } catch (error) {
    console.error('Error generating enriched report:', error)
    return NextResponse.json(
      { error: 'Failed to generate enriched report: ' + error.message },
      { status: 500 }
    )
  }
}

// Auto-detect technology stack from report content using heuristics
function autoDetectStack(report: any): string {
  const reportText = JSON.stringify(report).toLowerCase()
  console.log('Analyzing report for tech stack detection...')

  // Stack detection patterns with confidence scoring
  const stackPatterns = [
    {
      stack: 'php-laravel',
      patterns: ['php', 'laravel', 'apache', 'composer', 'blade', '.htaccess', 'mysqli', 'predis'],
      weight: 3
    },
    {
      stack: 'python-django',
      patterns: ['python', 'django', 'flask', 'jinja', 'wsgi', 'settings.py', 'virtualenv'],
      weight: 3
    },
    {
      stack: 'java-spring',
      patterns: ['java', 'spring', 'tomcat', 'jsp', 'thymeleaf', 'websecurityconfig', 'hibernate'],
      weight: 3
    },
    {
      stack: 'nextjs-vercel',
      patterns: ['next.js', 'vercel', 'react', 'next.config.js', 'middleware.ts', 'app router', 'use client'],
      weight: 3
    },
    {
      stack: 'static-nginx',
      patterns: ['nginx', 'apache', 'static html', '.conf', 'index.html', 'javascript:'],
      weight: 2
    },
    {
      stack: 'nodejs-express',
      patterns: ['node.js', 'express', 'morgan', 'body-parser', 'helmet'],
      weight: 2
    },
    {
      stack: 'asp.net',
      patterns: ['asp.net', 'web.config', 'c#', 'razor pages', 'global.asax', 'httpcontext'],
      weight: 2
    },
    {
      stack: 'wordpress',
      patterns: ['wordpress', 'wp-content', 'wp-includes', 'wp-json', 'wp-login'],
      weight: 2
    },
    {
      stack: 'ruby-rails',
      patterns: ['ruby', 'rails', 'gemfile', 'bundle', 'rack', 'puma'],
      weight: 2
    },
    {
      stack: 'go-gin',
      patterns: ['go', 'gin', 'golang', 'gorilla', 'mux', 'handler'],
      weight: 2
    },
  ]

  // Calculate scores for each stack
  const scores = stackPatterns.map(({ stack, patterns, weight }) => {
    let score = 0
    patterns.forEach(pattern => {
      const regex = new RegExp(pattern.toLowerCase(), 'gi')
      const matches = reportText.match(regex)
      if (matches) {
        score += matches.length * weight
      }
    })
    return { stack, score, matched: [] as string[] }
  })

  // Sort by score (highest first)
  scores.sort((a, b) => b.score - a.score)

  // Return best match or default to 'nextjs-vercel'
  const bestMatch = scores.find(s => s.score > 0)
  return bestMatch ? bestMatch.stack : 'nextjs-vercel'
}
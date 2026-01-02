import { Info, ChevronDown, ChevronUp } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'

interface InfoBannerProps {
  showInfo: boolean
  setShowInfo: (show: boolean) => void
}

export function InfoBanner({ showInfo, setShowInfo }: InfoBannerProps) {
  return (
    <Collapsible open={showInfo} onOpenChange={setShowInfo}>
      <div className="mb-8 bg-blue-50 dark:bg-blue-950 border-2 border-blue-200 dark:border-blue-900 rounded-xl">
        <CollapsibleTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start text-blue-800 dark:text-blue-200 hover:bg-blue-100 dark:hover:bg-blue-900"
          >
            <Info className="h-4 w-4 mr-2" />
            <span className="font-semibold">Understanding Security Scan Results</span>
            {showInfo ? (
              <ChevronUp className="h-4 w-4 ml-2" />
            ) : (
              <ChevronDown className="h-4 w-4 ml-2" />
            )}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="p-4 space-y-3">
            <div className="space-y-2">
              <h3 className="font-semibold text-blue-900 dark:text-blue-100 text-lg mb-2">
                📋 What the Scanner Checks
              </h3>
              <ul className="list-disc list-inside space-y-2 text-sm text-blue-800 dark:text-blue-200 ml-4">
                <li>
                  <strong>SSL/TLS:</strong> Certificate validity, encryption strength, and TLS version
                </li>
                <li>
                  <strong>Security Headers:</strong> CSP, HSTS, X-Frame-Options, and other HTTP headers
                </li>
                <li>
                  <strong>DNS Security:</strong> SPF, DMARC, DKIM (only if MX records exist)
                </li>
                <li>
                  <strong>Performance:</strong> Response time, compression, HTTP version
                </li>
                <li>
                  <strong>Vulnerabilities:</strong> Patterns found in HTML, JS, CSS, and configuration
                </li>
              </ul>
            </div>

            <div className="border-t border-blue-200 dark:border-blue-800 pt-3">
              <h3 className="font-semibold text-blue-900 dark:text-blue-100 text-lg mb-2">
                ⚠️ Understanding False Positives
              </h3>
              <p className="text-sm text-blue-800 dark:text-blue-200 mb-2">
                Some findings may be <strong>false positives</strong> - they appear in the report but don't actually exist in your code:
              </p>
              <ul className="list-disc list-inside space-y-2 text-sm text-blue-800 dark:text-blue-200 ml-4">
                <li>
                  <strong>Inline Event Handlers:</strong> The scanner checks the <em>target website's HTML</em>, not your source code. React components like onClick={} are safe.
                </li>
                <li>
                  <strong>Overly Permissive CORS:</strong> Client-side applications don't use CORS headers. Only API routes need CORS configuration.
                </li>
                <li>
                  <strong>No WAF Detected:</strong> Vercel has built-in protection that doesn't advertise itself in headers.
                </li>
                <li>
                  <strong>Meta Author/Generator:</strong> These are informational tags, not security vulnerabilities.
                </li>
              </ul>
            </div>

            <div className="border-t border-blue-200 dark:border-blue-800 pt-3">
              <h3 className="font-semibold text-blue-900 dark:text-blue-100 text-lg mb-2">
                🔍 How to Verify Issues
              </h3>
              <p className="text-sm text-blue-800 dark:text-blue-200 mb-2">
                To confirm if an issue is real, check:
              </p>
              <ol className="list-decimal list-inside space-y-1 text-sm text-blue-800 dark:text-blue-200 ml-4">
                <li>Search your <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded text-blue-900 dark:text-blue-100">src/app</code> directory</li>
                <li>Check <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded text-blue-900 dark:text-blue-100">src/components</code> for the pattern</li>
                <li>Review <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded text-blue-900 dark:text-blue-100">next.config.ts</code> for headers</li>
                <li>If not found, it's a false positive from the target site</li>
              </ol>
            </div>
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  )
}

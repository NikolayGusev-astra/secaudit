-- Supabase Database Schema for Security Audit Tool
-- Generated from Prisma schema for PostgreSQL

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom types (enums)
CREATE TYPE scan_status AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');
CREATE TYPE risk_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN');
CREATE TYPE vulnerability_type AS ENUM (
  'XSS', 'CSRF', 'SQL_INJECTION', 'SSRF', 'OPEN_REDIRECT',
  'INFORMATION_DISCLOSURE', 'MISCONFIGURATION', 'OUTDATED_SOFTWARE',
  'WEAK_PASSWORD', 'INSECURE_HEADERS', 'SSL_TLS_ISSUE', 'MISSING_ENCRYPTION',
  'VULNERABLE_LIBRARY', 'PORT_EXPOSED', 'DNS_ISSUE', 'OTHER'
);
CREATE TYPE severity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- Create User table
CREATE TABLE "User" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create Post table
CREATE TABLE "Post" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  title TEXT NOT NULL,
  content TEXT,
  published BOOLEAN DEFAULT false,
  "authorId" TEXT NOT NULL,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create SecurityScan table
CREATE TABLE "SecurityScan" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  status scan_status DEFAULT 'PENDING',
  "overallScore" INTEGER NOT NULL,
  "riskLevel" risk_level DEFAULT 'UNKNOWN',
  "startedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "completedAt" TIMESTAMP WITH TIME ZONE,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create SSLCheck table
CREATE TABLE "SSLCheck" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  "scanId" TEXT UNIQUE NOT NULL REFERENCES "SecurityScan"(id) ON DELETE CASCADE,
  "hasCertificate" BOOLEAN DEFAULT false,
  issuer TEXT,
  subject TEXT,
  "validFrom" TIMESTAMP WITH TIME ZONE,
  "validTo" TIMESTAMP WITH TIME ZONE,
  "daysUntilExpiry" INTEGER,
  "isValid" BOOLEAN DEFAULT false,
  "isSelfSigned" BOOLEAN DEFAULT false,
  "isExpired" BOOLEAN DEFAULT false,
  "isTrusted" BOOLEAN DEFAULT false,
  "tlsVersion" TEXT,
  "tlsVersions" TEXT,
  "cipherSuite" TEXT,
  "hasWeakCiphers" BOOLEAN DEFAULT false,
  "chainLength" INTEGER,
  "hasFullChain" BOOLEAN DEFAULT false,
  "hasOCSPStapling" BOOLEAN DEFAULT false,
  "hasCT" BOOLEAN DEFAULT false,
  issues TEXT,
  score INTEGER DEFAULT 0,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create SecurityHeaderCheck table
CREATE TABLE "SecurityHeaderCheck" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  "scanId" TEXT UNIQUE NOT NULL REFERENCES "SecurityScan"(id) ON DELETE CASCADE,
  "hasCSP" BOOLEAN DEFAULT false,
  "cspValue" TEXT,
  "hasHSTS" BOOLEAN DEFAULT false,
  "hstsValue" TEXT,
  "hstsMaxAge" INTEGER,
  "hasHSTSIncludeSubdomains" BOOLEAN DEFAULT false,
  "hasHSTSPreload" BOOLEAN DEFAULT false,
  "hasXFrameOptions" BOOLEAN DEFAULT false,
  "xFrameOptions" TEXT,
  "hasXContentTypeOptions" BOOLEAN DEFAULT false,
  "hasXSSProtection" BOOLEAN DEFAULT false,
  "xssProtection" TEXT,
  "hasReferrerPolicy" BOOLEAN DEFAULT false,
  "referrerPolicy" TEXT,
  "hasPermissionsPolicy" BOOLEAN DEFAULT false,
  "permissionsPolicy" TEXT,
  "hasStrictTransportSecurity" BOOLEAN DEFAULT false,
  "hasServerHeader" BOOLEAN DEFAULT false,
  "serverValue" TEXT,
  "hasXPoweredBy" BOOLEAN DEFAULT false,
  "missingHeaders" TEXT,
  issues TEXT,
  score INTEGER DEFAULT 0,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create DNSCheck table
CREATE TABLE "DNSCheck" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  "scanId" TEXT UNIQUE NOT NULL REFERENCES "SecurityScan"(id) ON DELETE CASCADE,
  "hasARecord" BOOLEAN DEFAULT false,
  "hasAAAARecord" BOOLEAN DEFAULT false,
  "hasMXRecord" BOOLEAN DEFAULT false,
  "hasTXTRecord" BOOLEAN DEFAULT false,
  "hasNSRecord" BOOLEAN DEFAULT false,
  "hasSPF" BOOLEAN DEFAULT false,
  "spfRecord" TEXT,
  "spfValid" BOOLEAN DEFAULT false,
  "hasDMARC" BOOLEAN DEFAULT false,
  "dmarcRecord" TEXT,
  "dmarcPolicy" TEXT,
  "dmarcValid" BOOLEAN DEFAULT false,
  "hasDKIM" BOOLEAN DEFAULT false,
  "hasDNSSEC" BOOLEAN DEFAULT false,
  "dnsRecords" TEXT,
  issues TEXT,
  score INTEGER DEFAULT 0,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create PerformanceCheck table
CREATE TABLE "PerformanceCheck" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  "scanId" TEXT UNIQUE NOT NULL REFERENCES "SecurityScan"(id) ON DELETE CASCADE,
  "statusCode" INTEGER DEFAULT 0,
  "responseTime" INTEGER NOT NULL,
  ttfb INTEGER,
  "domContentLoaded" INTEGER,
  "loadComplete" INTEGER,
  "totalSize" INTEGER,
  "htmlSize" INTEGER,
  "cssSize" INTEGER,
  "jsSize" INTEGER,
  "imageSize" INTEGER,
  "totalResources" INTEGER,
  "scriptCount" INTEGER,
  "stylesheetCount" INTEGER,
  "imageCount" INTEGER,
  "hasGzip" BOOLEAN DEFAULT false,
  "hasBrotli" BOOLEAN DEFAULT false,
  "compressionSavings" INTEGER,
  "hasCacheControl" BOOLEAN DEFAULT false,
  "hasETag" BOOLEAN DEFAULT false,
  "hasLastModified" BOOLEAN DEFAULT false,
  "httpVersion" TEXT,
  recommendations TEXT,
  score INTEGER DEFAULT 0,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create VulnerabilityCheck table
CREATE TABLE "VulnerabilityCheck" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  "scanId" TEXT NOT NULL REFERENCES "SecurityScan"(id) ON DELETE CASCADE,
  type vulnerability_type NOT NULL,
  severity severity NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  url TEXT,
  evidence TEXT,
  "owaspCategory" TEXT,
  recommendation TEXT NOT NULL,
  "cveId" TEXT,
  "isFalsePositive" BOOLEAN DEFAULT false,
  "isConfirmed" BOOLEAN DEFAULT true,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create PortScan table
CREATE TABLE "PortScan" (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  "scanId" TEXT NOT NULL REFERENCES "SecurityScan"(id) ON DELETE CASCADE,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  state TEXT NOT NULL,
  service TEXT,
  version TEXT,
  risk severity DEFAULT 'INFO',
  description TEXT,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_security_scan_domain ON "SecurityScan"(domain);
CREATE INDEX idx_security_scan_status ON "SecurityScan"(status);
CREATE INDEX idx_security_scan_created_at ON "SecurityScan"("createdAt");

-- Add foreign key constraint for Post table
ALTER TABLE "Post" ADD CONSTRAINT "Post_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User"(id) ON DELETE RESTRICT ON UPDATE CASCADE;

-- Enable Row Level Security (RLS) for all tables
ALTER TABLE "User" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Post" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "SecurityScan" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "SSLCheck" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "SecurityHeaderCheck" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "DNSCheck" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PerformanceCheck" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "VulnerabilityCheck" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PortScan" ENABLE ROW LEVEL SECURITY;

-- Create policies for public access (you may want to restrict these based on your auth requirements)
CREATE POLICY "Allow all operations on User" ON "User" FOR ALL USING (true);
CREATE POLICY "Allow all operations on Post" ON "Post" FOR ALL USING (true);
CREATE POLICY "Allow all operations on SecurityScan" ON "SecurityScan" FOR ALL USING (true);
CREATE POLICY "Allow all operations on SSLCheck" ON "SSLCheck" FOR ALL USING (true);
CREATE POLICY "Allow all operations on SecurityHeaderCheck" ON "SecurityHeaderCheck" FOR ALL USING (true);
CREATE POLICY "Allow all operations on DNSCheck" ON "DNSCheck" FOR ALL USING (true);
CREATE POLICY "Allow all operations on PerformanceCheck" ON "PerformanceCheck" FOR ALL USING (true);
CREATE POLICY "Allow all operations on VulnerabilityCheck" ON "VulnerabilityCheck" FOR ALL USING (true);
CREATE POLICY "Allow all operations on PortScan" ON "PortScan" FOR ALL USING (true);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW."updatedAt" = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Add updated_at triggers to tables that have this column
CREATE TRIGGER update_user_updated_at BEFORE UPDATE ON "User" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_post_updated_at BEFORE UPDATE ON "Post" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_security_scan_updated_at BEFORE UPDATE ON "SecurityScan" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_ssl_check_updated_at BEFORE UPDATE ON "SSLCheck" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_security_header_check_updated_at BEFORE UPDATE ON "SecurityHeaderCheck" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dns_check_updated_at BEFORE UPDATE ON "DNSCheck" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_performance_check_updated_at BEFORE UPDATE ON "PerformanceCheck" FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
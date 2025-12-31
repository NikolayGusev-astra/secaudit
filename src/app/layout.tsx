import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Security Audit for VibeCoders",
  description: "Professional-grade security and performance scanner. Analyze your website for vulnerabilities, security misconfigurations, and performance issues.",
  keywords: ["Security Audit", "Vulnerability Scanner", "Website Security", "Performance Analysis", "OWASP", "Penetration Testing"],
  authors: [{ name: "VibeCoders Team" }],
  icons: {
    icon: "/logo.svg",
  },
  openGraph: {
    title: "Security Audit for VibeCoders",
    description: "Professional-grade security and performance scanner. Analyze your website for vulnerabilities, security misconfigurations, and performance issues.",
    url: "https://secaudit-pi.vercel.app",
    siteName: "Security Audit for VibeCoders",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Security Audit for VibeCoders",
    description: "Professional-grade security and performance scanner. Analyze your website for vulnerabilities, security misconfigurations, and performance issues.",
  },
  other: {
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
'use client'

import type { Metadata, ReactNode } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";
import { LanguageProvider } from "@/lib/language-context";

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
  icons: {
    icon: "/logo.svg",
  },
  openGraph: {
    title: "Security Audit for VibeCoders",
    description: "Professional-grade security and performance scanner. Analyze your website for vulnerabilities, security misconfigurations, and performance issues.",
    url: "https://secaudit-pi.vercel.app",
    siteName: "Security Audit for VibeCoders",
    type: "website",
    images: [{
      url: "https://secaudit-pi.vercel.app/logo.svg",
      width: 512,
      height: 512,
      alt: "Security Audit Logo"
    }]
  },
  twitter: {
    card: "summary_large_image",
    title: "Security Audit for VibeCoders",
    description: "Professional-grade security and performance scanner. Analyze your website for vulnerabilities, security misconfigurations, and performance issues.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: ReactNode;
}>) {
  return (
    <LanguageProvider>
      <html lang="en" suppressHydrationWarning>
        <body
          className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
        >
          {children}
          <Toaster />
        </body>
      </html>
    </LanguageProvider>
  );
}

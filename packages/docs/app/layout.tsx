import { Footer, Layout, Navbar } from 'nextra-theme-docs'
import { Head } from 'nextra/components'
import { getPageMap } from 'nextra/page-map'
import 'nextra-theme-docs/style.css'
import '../styles/globals.css'
import type { ReactNode } from 'react'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: {
    template: '%s – SentriFlow Docs',
    default: 'SentriFlow Docs',
  },
  description: 'Network configuration compliance validation framework. Validate Cisco, Juniper, Aruba, and more.',
  keywords: ['network', 'configuration', 'compliance', 'validation', 'cisco', 'juniper', 'security', 'hardening', 'audit', 'network config audit tool', 'cisco ios best practices'],
  openGraph: {
    title: 'SentriFlow Documentation',
    description: 'Network configuration compliance validation framework',
    siteName: 'SentriFlow Docs',
    locale: 'en_US',
    type: 'website',
    images: [
      {
        url: 'https://docs.sentriflow.com.au/og-image.png',
        width: 1200,
        height: 630,
        alt: 'SentriFlow - Network Configuration Compliance Validation',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SentriFlow Documentation',
    description: 'Network configuration compliance validation framework',
    images: ['https://docs.sentriflow.com.au/og-image.png'],
  },
}

// Logo component
const Logo = () => (
  <div className="flex items-center gap-2">
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="text-cyan-400"
    >
      <path
        d="M12 2L2 7L12 12L22 7L12 2Z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M2 17L12 22L22 17"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M2 12L12 17L22 12"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
    <span className="font-bold text-lg">SentriFlow</span>
  </div>
)

// Navbar component
const navbar = (
  <Navbar
    logo={<Logo />}
    projectLink="https://github.com/sentriflow/sentriflow"
  />
)

// Footer component
const footer = (
  <Footer>
    <div className="flex w-full flex-col items-center sm:items-start">
      <p className="text-xs">
        MIT {new Date().getFullYear()} © SentriFlow. Network configuration compliance validation framework.
      </p>
    </div>
  </Footer>
)

// JSON-LD structured data for Organization schema
const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'SentriFlow',
  url: 'https://sentriflow.com.au',
  logo: 'https://docs.sentriflow.com.au/og-image.png',
  description: 'Open-source network configuration compliance validation framework.',
  sameAs: [
    'https://github.com/sentriflow/sentriflow',
    'https://discord.gg/ZWsEfUW5',
  ],
}

export default async function RootLayout({ children }: { children: ReactNode }) {
  const pageMap = await getPageMap()

  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head faviconGlyph="⚡" />
      <body>
        <script
          type="application/ld+json"
          // Safe: static object from source code, not user input
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <Layout
          navbar={navbar}
          pageMap={pageMap}
          docsRepositoryBase="https://github.com/sentriflow/sentriflow/tree/main/packages/docs"
          footer={footer}
          editLink="Edit this page on GitHub"
          sidebar={{ defaultMenuCollapseLevel: 1, toggleButton: true }}
          toc={{ float: true, title: 'On This Page', backToTop: true }}
        >
          {children}
        </Layout>
      </body>
    </html>
  )
}

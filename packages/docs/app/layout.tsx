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

export default async function RootLayout({ children }: { children: ReactNode }) {
  const pageMap = await getPageMap()

  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head faviconGlyph="⚡" />
      <body>
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

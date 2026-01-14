import type React from 'react';

// Theme configuration for SentriFlow documentation
// This file is referenced by next.config.mjs themeConfig option
// Configuration options are validated at runtime by Nextra
const config = {
  // Logo configuration
  logo: (
    <div className="flex items-center gap-2">
      <svg
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="text-sf-cyan"
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
  ),

  // Documentation repository base for edit links
  docsRepositoryBase: 'https://github.com/sentriflow/sentriflow/tree/main/packages/docs',

  // Dark mode configuration - enable toggle
  darkMode: true,

  // Navigation configuration
  navigation: {
    prev: true,
    next: true,
  },

  // Sidebar configuration
  sidebar: {
    defaultMenuCollapseLevel: 1,
    toggleButton: true,
  },

  // Table of Contents configuration
  toc: {
    float: true,
    title: 'On This Page',
    backToTop: true,
  },

  // Edit link configuration
  editLink: 'Edit this page on GitHub',

  // Feedback link configuration
  feedback: {
    content: 'Question? Give us feedback →',
    labels: 'feedback',
  },

  // Footer configuration
  footer: (
    <div className="flex w-full flex-col items-center sm:items-start">
      <div className="mb-2">
        <a
          className="flex items-center gap-2 text-current hover:opacity-75"
          href="https://github.com/sentriflow/sentriflow"
          target="_blank"
          rel="noopener noreferrer"
        >
          <span className="font-semibold">SentriFlow</span>
        </a>
      </div>
      <p className="mt-4 text-xs">
        MIT {new Date().getFullYear()} © SentriFlow. Network configuration
        compliance validation framework.
      </p>
    </div>
  ),

  // Last updated component
  lastUpdated: (
    <div className="text-xs text-gray-500">
      <span>Last updated on {new Date().toLocaleDateString()}</span>
    </div>
  ),
};

export default config;

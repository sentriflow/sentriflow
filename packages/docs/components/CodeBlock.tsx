'use client'

import { useState } from 'react'
import type { ReactNode } from 'react'

export interface CodeBlockProps {
  children: string
  language?: string
  filename?: string
  showLineNumbers?: boolean
  className?: string
}

export function CodeBlock({
  children,
  language = 'text',
  filename,
  showLineNumbers = false,
  className = '',
}: CodeBlockProps): ReactNode {
  const [copied, setCopied] = useState(false)

  const handleCopy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(children)
      setCopied(true)
      setTimeout(() => {
        setCopied(false)
      }, 2000)
    } catch (error) {
      console.error('Failed to copy code:', error)
    }
  }

  const handleKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>): void => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      void handleCopy()
    }
  }

  const lines = children.split('\n')
  const codeContent = showLineNumbers
    ? lines.map((line, index) => (
        <div key={index} className="flex">
          <span className="select-none pr-4 text-sf-gray-500 text-right min-w-[3ch]">
            {index + 1}
          </span>
          <span className="flex-1">{line}</span>
        </div>
      ))
    : children

  return (
    <div className="relative group my-6 rounded-lg overflow-hidden bg-sf-graphite border border-sf-slate">
      {filename !== undefined && filename !== '' && (
        <div className="flex items-center justify-between px-4 py-2 bg-sf-charcoal border-b border-sf-slate">
          <span className="text-sm font-mono text-sf-gray-400">{filename}</span>
          {language !== 'text' && (
            <span className="text-xs font-mono text-sf-gray-500 uppercase">
              {language}
            </span>
          )}
        </div>
      )}

      <div className="relative">
        <pre
          className={`overflow-x-auto p-4 font-mono text-sm text-sf-gray-100 ${className}`}
        >
          <code className={`language-${language}`}>
            {showLineNumbers ? codeContent : children}
          </code>
        </pre>

        <button
          type="button"
          onClick={() => {
            void handleCopy()
          }}
          onKeyDown={handleKeyDown}
          className={`
            absolute top-3 right-3
            px-3 py-1.5
            text-xs font-medium
            rounded-md
            transition-all duration-200
            opacity-0 group-hover:opacity-100 focus:opacity-100
            ${
              copied
                ? 'bg-sf-teal/20 text-sf-teal border border-sf-teal/40'
                : 'bg-sf-slate/80 text-sf-gray-300 border border-sf-gray-700 hover:bg-sf-slate hover:text-sf-cyan'
            }
            focus:outline-none focus:ring-2 focus:ring-sf-cyan focus:ring-offset-2 focus:ring-offset-sf-graphite
          `}
          aria-label={copied ? 'Code copied to clipboard' : 'Copy code to clipboard'}
          aria-live="polite"
        >
          {copied ? (
            <span className="flex items-center gap-1.5">
              <svg
                className="w-3.5 h-3.5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
              Copied!
            </span>
          ) : (
            <span className="flex items-center gap-1.5">
              <svg
                className="w-3.5 h-3.5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                />
              </svg>
              Copy
            </span>
          )}
        </button>
      </div>
    </div>
  )
}

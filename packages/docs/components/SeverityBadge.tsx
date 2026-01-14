'use client'

import type { ReactNode } from 'react'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface SeverityBadgeProps {
  severity: Severity
  cvssScore?: number
  size?: 'sm' | 'md' | 'lg'
  showLabel?: boolean
  className?: string
}

const severityConfig = {
  critical: {
    bgColor: 'bg-red-500',
    textColor: 'text-white',
    borderColor: 'border-red-600',
    label: 'Critical',
    icon: (
      <svg
        width="100%"
        height="100%"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
      </svg>
    ),
  },
  high: {
    bgColor: 'bg-orange-500',
    textColor: 'text-white',
    borderColor: 'border-orange-600',
    label: 'High',
    icon: (
      <svg
        width="100%"
        height="100%"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
      </svg>
    ),
  },
  medium: {
    bgColor: 'bg-yellow-500',
    textColor: 'text-gray-900',
    borderColor: 'border-yellow-600',
    label: 'Medium',
    icon: null,
  },
  low: {
    bgColor: 'bg-blue-500',
    textColor: 'text-white',
    borderColor: 'border-blue-600',
    label: 'Low',
    icon: null,
  },
  info: {
    bgColor: 'bg-gray-500',
    textColor: 'text-white',
    borderColor: 'border-gray-600',
    label: 'Info',
    icon: null,
  },
} as const

const sizeConfig = {
  sm: {
    padding: 'px-2 py-0.5',
    textSize: 'text-xs',
    iconSize: 12, // 0.75rem = 12px
    gap: 'gap-1',
  },
  md: {
    padding: 'px-2.5 py-1',
    textSize: 'text-sm',
    iconSize: 14, // 0.875rem = 14px
    gap: 'gap-1.5',
  },
  lg: {
    padding: 'px-3 py-1.5',
    textSize: 'text-base',
    iconSize: 16, // 1rem = 16px
    gap: 'gap-2',
  },
} as const

export function SeverityBadge({
  severity,
  cvssScore,
  size = 'md',
  showLabel = true,
  className = '',
}: SeverityBadgeProps): ReactNode {
  const config = severityConfig[severity]
  const sizeStyles = sizeConfig[size]

  // Validate CVSS score if provided
  const validCvssScore =
    cvssScore !== undefined && cvssScore >= 0 && cvssScore <= 10
      ? cvssScore.toFixed(1)
      : null

  const hasIcon = config.icon !== null && (severity === 'critical' || severity === 'high')

  return (
    <span
      className={`
        inline-flex items-center
        ${sizeStyles.padding}
        ${sizeStyles.gap}
        ${sizeStyles.textSize}
        ${config.bgColor}
        ${config.textColor}
        border ${config.borderColor}
        rounded-full
        font-medium
        ${className}
      `}
      role="status"
      aria-label={`Severity: ${config.label}${validCvssScore !== null ? `, CVSS Score: ${validCvssScore}` : ''}`}
    >
      {hasIcon && (
        <span
          className="inline-block flex-shrink-0 overflow-hidden"
          style={{ width: sizeStyles.iconSize, height: sizeStyles.iconSize }}
        >
          {config.icon}
        </span>
      )}
      {showLabel && <span>{config.label}</span>}
      {validCvssScore !== null && (
        <span className="font-normal opacity-90">({validCvssScore})</span>
      )}
    </span>
  )
}

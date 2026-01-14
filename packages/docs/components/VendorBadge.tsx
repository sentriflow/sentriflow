'use client'

import type { ReactNode } from 'react'

export interface VendorBadgeProps {
  vendor: string
  size?: 'sm' | 'md' | 'lg'
  showIcon?: boolean
  onClick?: () => void
  className?: string
}

// Vendor configuration mapping
interface VendorConfig {
  displayName: string
  family: string
  color: {
    bg: string
    text: string
    border: string
    hoverBg: string
  }
  icon?: string
}

const VENDOR_CONFIGS: Record<string, VendorConfig> = {
  // Cisco family (blue theme)
  'cisco-ios': {
    displayName: 'Cisco IOS',
    family: 'cisco',
    color: {
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      border: 'border-blue-500/30',
      hoverBg: 'hover:bg-blue-500/20',
    },
    icon: '🔷',
  },
  'cisco-nxos': {
    displayName: 'Cisco NX-OS',
    family: 'cisco',
    color: {
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      border: 'border-blue-500/30',
      hoverBg: 'hover:bg-blue-500/20',
    },
    icon: '🔷',
  },

  // Juniper family (green theme)
  'juniper-junos': {
    displayName: 'Juniper Junos',
    family: 'juniper',
    color: {
      bg: 'bg-green-500/10',
      text: 'text-green-400',
      border: 'border-green-500/30',
      hoverBg: 'hover:bg-green-500/20',
    },
    icon: '🌲',
  },

  // Aruba family (orange theme)
  'aruba-aoscx': {
    displayName: 'Aruba AOS-CX',
    family: 'aruba',
    color: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      hoverBg: 'hover:bg-orange-500/20',
    },
    icon: '📡',
  },
  'aruba-aosswitch': {
    displayName: 'Aruba AOS-Switch',
    family: 'aruba',
    color: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      hoverBg: 'hover:bg-orange-500/20',
    },
    icon: '📡',
  },
  'aruba-wlc': {
    displayName: 'Aruba WLC',
    family: 'aruba',
    color: {
      bg: 'bg-orange-500/10',
      text: 'text-orange-400',
      border: 'border-orange-500/30',
      hoverBg: 'hover:bg-orange-500/20',
    },
    icon: '📡',
  },

  // Palo Alto (red theme)
  'paloalto-panos': {
    displayName: 'Palo Alto PAN-OS',
    family: 'paloalto',
    color: {
      bg: 'bg-red-500/10',
      text: 'text-red-400',
      border: 'border-red-500/30',
      hoverBg: 'hover:bg-red-500/20',
    },
    icon: '🛡️',
  },

  // Arista (purple theme)
  'arista-eos': {
    displayName: 'Arista EOS',
    family: 'arista',
    color: {
      bg: 'bg-purple-500/10',
      text: 'text-purple-400',
      border: 'border-purple-500/30',
      hoverBg: 'hover:bg-purple-500/20',
    },
    icon: '⚡',
  },

  // VyOS (cyan theme)
  vyos: {
    displayName: 'VyOS',
    family: 'vyos',
    color: {
      bg: 'bg-sf-cyan/10',
      text: 'text-sf-cyan',
      border: 'border-sf-cyan/30',
      hoverBg: 'hover:bg-sf-cyan/20',
    },
    icon: '🐧',
  },

  // Fortinet (rose theme)
  'fortinet-fortigate': {
    displayName: 'Fortinet FortiGate',
    family: 'fortinet',
    color: {
      bg: 'bg-rose-500/10',
      text: 'text-rose-400',
      border: 'border-rose-500/30',
      hoverBg: 'hover:bg-rose-500/20',
    },
    icon: '🔒',
  },

  // Extreme (indigo theme)
  'extreme-exos': {
    displayName: 'Extreme EXOS',
    family: 'extreme',
    color: {
      bg: 'bg-indigo-500/10',
      text: 'text-indigo-400',
      border: 'border-indigo-500/30',
      hoverBg: 'hover:bg-indigo-500/20',
    },
    icon: '⚙️',
  },
  'extreme-voss': {
    displayName: 'Extreme VOSS',
    family: 'extreme',
    color: {
      bg: 'bg-indigo-500/10',
      text: 'text-indigo-400',
      border: 'border-indigo-500/30',
      hoverBg: 'hover:bg-indigo-500/20',
    },
    icon: '⚙️',
  },

  // Huawei (yellow theme)
  'huawei-vrp': {
    displayName: 'Huawei VRP',
    family: 'huawei',
    color: {
      bg: 'bg-yellow-500/10',
      text: 'text-yellow-400',
      border: 'border-yellow-500/30',
      hoverBg: 'hover:bg-yellow-500/20',
    },
    icon: '🏢',
  },

  // MikroTik (teal theme)
  'mikrotik-routeros': {
    displayName: 'MikroTik RouterOS',
    family: 'mikrotik',
    color: {
      bg: 'bg-sf-teal/10',
      text: 'text-sf-teal',
      border: 'border-sf-teal/30',
      hoverBg: 'hover:bg-sf-teal/20',
    },
    icon: '🔧',
  },

  // Nokia (sky theme)
  'nokia-sros': {
    displayName: 'Nokia SR OS',
    family: 'nokia',
    color: {
      bg: 'bg-sky-500/10',
      text: 'text-sky-400',
      border: 'border-sky-500/30',
      hoverBg: 'hover:bg-sky-500/20',
    },
    icon: '📱',
  },

  // Cumulus (lime theme)
  'cumulus-linux': {
    displayName: 'Cumulus Linux',
    family: 'cumulus',
    color: {
      bg: 'bg-lime-500/10',
      text: 'text-lime-400',
      border: 'border-lime-500/30',
      hoverBg: 'hover:bg-lime-500/20',
    },
    icon: '☁️',
  },

  // Common (gray theme)
  common: {
    displayName: 'Common',
    family: 'common',
    color: {
      bg: 'bg-sf-gray-500/10',
      text: 'text-sf-gray-400',
      border: 'border-sf-gray-500/30',
      hoverBg: 'hover:bg-sf-gray-500/20',
    },
    icon: '📋',
  },
}

// Size configuration
const SIZE_CLASSES = {
  sm: {
    padding: 'px-2 py-0.5',
    text: 'text-xs',
    icon: 'text-sm',
    gap: 'gap-1',
  },
  md: {
    padding: 'px-3 py-1',
    text: 'text-sm',
    icon: 'text-base',
    gap: 'gap-1.5',
  },
  lg: {
    padding: 'px-4 py-1.5',
    text: 'text-base',
    icon: 'text-lg',
    gap: 'gap-2',
  },
} as const

export function VendorBadge({
  vendor,
  size = 'md',
  showIcon = true,
  onClick,
  className = '',
}: VendorBadgeProps): ReactNode {
  // Get vendor configuration or fallback to unknown vendor
  const config = VENDOR_CONFIGS[vendor] ?? {
    displayName: vendor,
    family: 'unknown',
    color: {
      bg: 'bg-sf-gray-600/10',
      text: 'text-sf-gray-400',
      border: 'border-sf-gray-600/30',
      hoverBg: 'hover:bg-sf-gray-600/20',
    },
    icon: '❓',
  }

  const sizeClasses = SIZE_CLASSES[size]
  const isClickable = onClick !== undefined

  const baseClasses = `
    inline-flex items-center
    ${sizeClasses.gap}
    ${sizeClasses.padding}
    ${sizeClasses.text}
    font-medium
    rounded-full
    border
    ${config.color.bg}
    ${config.color.text}
    ${config.color.border}
    transition-all duration-200
    ${isClickable ? `cursor-pointer ${config.color.hoverBg} hover:shadow-md active:scale-95` : ''}
    ${isClickable ? 'focus:outline-none focus:ring-2 focus:ring-sf-cyan focus:ring-offset-2 focus:ring-offset-sf-graphite' : ''}
    ${className}
  `.trim()

  const handleKeyDown = (event: React.KeyboardEvent<HTMLElement>): void => {
    if (isClickable && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault()
      onClick()
    }
  }

  const content = (
    <>
      {showIcon && config.icon !== undefined && (
        <span className={sizeClasses.icon} aria-hidden="true">
          {config.icon}
        </span>
      )}
      <span>{config.displayName}</span>
    </>
  )

  if (isClickable) {
    return (
      <button
        type="button"
        onClick={onClick}
        onKeyDown={handleKeyDown}
        className={baseClasses}
        aria-label={`Filter by ${config.displayName}`}
      >
        {content}
      </button>
    )
  }

  return (
    <span className={baseClasses} aria-label={config.displayName}>
      {content}
    </span>
  )
}

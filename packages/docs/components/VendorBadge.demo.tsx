/**
 * Demo file for VendorBadge component
 * This file demonstrates all variants and use cases
 */

import { VendorBadge } from './VendorBadge'

export function VendorBadgeDemo() {
  return (
    <div className="p-8 space-y-8 bg-sf-charcoal min-h-screen">
      {/* Size variants */}
      <section>
        <h2 className="text-2xl font-bold text-sf-white mb-4">Size Variants</h2>
        <div className="flex flex-wrap gap-4 items-center">
          <VendorBadge vendor="cisco-ios" size="sm" />
          <VendorBadge vendor="cisco-ios" size="md" />
          <VendorBadge vendor="cisco-ios" size="lg" />
        </div>
      </section>

      {/* All vendors */}
      <section>
        <h2 className="text-2xl font-bold text-sf-white mb-4">All Supported Vendors</h2>
        <div className="flex flex-wrap gap-3">
          {/* Cisco */}
          <VendorBadge vendor="cisco-ios" />
          <VendorBadge vendor="cisco-nxos" />

          {/* Juniper */}
          <VendorBadge vendor="juniper-junos" />

          {/* Aruba */}
          <VendorBadge vendor="aruba-aoscx" />
          <VendorBadge vendor="aruba-aosswitch" />
          <VendorBadge vendor="aruba-wlc" />

          {/* Palo Alto */}
          <VendorBadge vendor="paloalto-panos" />

          {/* Arista */}
          <VendorBadge vendor="arista-eos" />

          {/* VyOS */}
          <VendorBadge vendor="vyos" />

          {/* Fortinet */}
          <VendorBadge vendor="fortinet-fortigate" />

          {/* Extreme */}
          <VendorBadge vendor="extreme-exos" />
          <VendorBadge vendor="extreme-voss" />

          {/* Huawei */}
          <VendorBadge vendor="huawei-vrp" />

          {/* MikroTik */}
          <VendorBadge vendor="mikrotik-routeros" />

          {/* Nokia */}
          <VendorBadge vendor="nokia-sros" />

          {/* Cumulus */}
          <VendorBadge vendor="cumulus-linux" />

          {/* Common */}
          <VendorBadge vendor="common" />
        </div>
      </section>

      {/* Without icons */}
      <section>
        <h2 className="text-2xl font-bold text-sf-white mb-4">Without Icons</h2>
        <div className="flex flex-wrap gap-3">
          <VendorBadge vendor="cisco-ios" showIcon={false} />
          <VendorBadge vendor="juniper-junos" showIcon={false} />
          <VendorBadge vendor="arista-eos" showIcon={false} />
        </div>
      </section>

      {/* Clickable badges */}
      <section>
        <h2 className="text-2xl font-bold text-sf-white mb-4">
          Clickable Badges (Click to see alert)
        </h2>
        <div className="flex flex-wrap gap-3">
          <VendorBadge
            vendor="cisco-ios"
            onClick={() => {
              alert('Filtered by Cisco IOS')
            }}
          />
          <VendorBadge
            vendor="juniper-junos"
            onClick={() => {
              alert('Filtered by Juniper Junos')
            }}
          />
          <VendorBadge
            vendor="paloalto-panos"
            onClick={() => {
              alert('Filtered by Palo Alto PAN-OS')
            }}
          />
        </div>
      </section>

      {/* Unknown vendor */}
      <section>
        <h2 className="text-2xl font-bold text-sf-white mb-4">Unknown Vendor Fallback</h2>
        <div className="flex flex-wrap gap-3">
          <VendorBadge vendor="unknown-vendor" />
          <VendorBadge vendor="custom-platform" />
        </div>
      </section>

      {/* Custom className */}
      <section>
        <h2 className="text-2xl font-bold text-sf-white mb-4">Custom Styling</h2>
        <div className="flex flex-wrap gap-3">
          <VendorBadge vendor="cisco-ios" className="shadow-lg shadow-blue-500/50" />
          <VendorBadge vendor="juniper-junos" className="shadow-lg shadow-green-500/50" />
        </div>
      </section>
    </div>
  )
}

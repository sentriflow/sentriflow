# VendorBadge Component

A production-ready React component for displaying network device vendor badges with icons, custom styling, and interactive features.

## Features

- **17 Supported Vendors** with unique color schemes and icons
- **Size Variants**: `sm`, `md`, `lg`
- **Optional Icons**: Toggle vendor-specific emoji icons
- **Clickable**: Optional `onClick` handler for filtering
- **Accessibility**: Full keyboard navigation, ARIA labels, focus indicators
- **TypeScript**: Strict typing with proper type exports
- **Tailwind CSS**: Uses SentriFlow design tokens
- **Unknown Vendor Fallback**: Gracefully handles unsupported vendors

## Supported Vendors

| Vendor ID | Display Name | Family | Icon | Color |
|-----------|--------------|--------|------|-------|
| `cisco-ios` | Cisco IOS | cisco | 🔷 | Blue |
| `cisco-nxos` | Cisco NX-OS | cisco | 🔷 | Blue |
| `juniper-junos` | Juniper Junos | juniper | 🌲 | Green |
| `aruba-aoscx` | Aruba AOS-CX | aruba | 📡 | Orange |
| `aruba-aosswitch` | Aruba AOS-Switch | aruba | 📡 | Orange |
| `aruba-wlc` | Aruba WLC | aruba | 📡 | Orange |
| `paloalto-panos` | Palo Alto PAN-OS | paloalto | 🛡️ | Red |
| `arista-eos` | Arista EOS | arista | ⚡ | Purple |
| `vyos` | VyOS | vyos | 🐧 | Cyan |
| `fortinet-fortigate` | Fortinet FortiGate | fortinet | 🔒 | Rose |
| `extreme-exos` | Extreme EXOS | extreme | ⚙️ | Indigo |
| `extreme-voss` | Extreme VOSS | extreme | ⚙️ | Indigo |
| `huawei-vrp` | Huawei VRP | huawei | 🏢 | Yellow |
| `mikrotik-routeros` | MikroTik RouterOS | mikrotik | 🔧 | Teal |
| `nokia-sros` | Nokia SR OS | nokia | 📱 | Sky |
| `cumulus-linux` | Cumulus Linux | cumulus | ☁️ | Lime |
| `common` | Common | common | 📋 | Gray |

## Usage

### Basic Usage

```tsx
import { VendorBadge } from '@/components/VendorBadge'

export function Example() {
  return <VendorBadge vendor="cisco-ios" />
}
```

### Size Variants

```tsx
<VendorBadge vendor="cisco-ios" size="sm" />
<VendorBadge vendor="cisco-ios" size="md" /> {/* default */}
<VendorBadge vendor="cisco-ios" size="lg" />
```

### Without Icon

```tsx
<VendorBadge vendor="juniper-junos" showIcon={false} />
```

### Clickable Badge (for filtering)

```tsx
<VendorBadge
  vendor="paloalto-panos"
  onClick={() => handleFilter('paloalto-panos')}
/>
```

### Custom Styling

```tsx
<VendorBadge
  vendor="arista-eos"
  className="shadow-lg shadow-purple-500/50"
/>
```

### Unknown Vendor Fallback

```tsx
{/* Automatically shows gray badge with "❓" icon */}
<VendorBadge vendor="unknown-platform" />
```

## Props

```typescript
export interface VendorBadgeProps {
  vendor: string           // Vendor ID (e.g., 'cisco-ios')
  size?: 'sm' | 'md' | 'lg' // Size variant (default: 'md')
  showIcon?: boolean       // Show vendor icon (default: true)
  onClick?: () => void     // Optional click handler
  className?: string       // Additional CSS classes
}
```

## Accessibility

- **Keyboard Navigation**: Full support for Tab, Enter, and Space key interactions
- **ARIA Labels**: Descriptive labels for screen readers
- **Focus Indicators**: Visible focus ring (2px cyan)
- **Semantic HTML**: Uses `<button>` for clickable badges, `<span>` for static

### Keyboard Shortcuts

- **Tab**: Navigate to badge
- **Enter** or **Space**: Activate clickable badge
- **Shift+Tab**: Navigate backwards

## Styling

The component uses SentriFlow design tokens from `tailwind.config.ts`:

- **Colors**: Vendor-specific color schemes with opacity variants
- **Typography**: Inter font (sans-serif)
- **Spacing**: Consistent padding based on size variant
- **Transitions**: Smooth 200ms transitions for hover/focus states

### Size Classes

| Size | Padding | Text | Icon | Gap |
|------|---------|------|------|-----|
| `sm` | `px-2 py-0.5` | `text-xs` | `text-sm` | `gap-1` |
| `md` | `px-3 py-1` | `text-sm` | `text-base` | `gap-1.5` |
| `lg` | `px-4 py-1.5` | `text-base` | `text-lg` | `gap-2` |

## Examples

### Vendor Filter Grid

```tsx
const vendors = [
  'cisco-ios',
  'juniper-junos',
  'aruba-aoscx',
  'paloalto-panos',
]

export function VendorFilter() {
  const [selected, setSelected] = useState<string | null>(null)

  return (
    <div className="flex flex-wrap gap-3">
      {vendors.map((vendor) => (
        <VendorBadge
          key={vendor}
          vendor={vendor}
          onClick={() => setSelected(vendor)}
          className={selected === vendor ? 'ring-2 ring-sf-cyan' : ''}
        />
      ))}
    </div>
  )
}
```

### Rule Documentation

```tsx
export function RuleCard({ rule }: { rule: Rule }) {
  return (
    <div className="border border-sf-slate rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-semibold">{rule.id}</h3>
        <div className="flex gap-2">
          {rule.vendors.map((vendor) => (
            <VendorBadge key={vendor} vendor={vendor} size="sm" />
          ))}
        </div>
      </div>
      <p className="text-sf-gray-400">{rule.description}</p>
    </div>
  )
}
```

## TypeScript

The component is fully typed with strict TypeScript settings:

- `strict: true`
- `noUncheckedIndexedAccess: true`
- `noImplicitReturns: true`

All props are typed with proper interfaces exported for reuse.

## Testing

To test the component, see `VendorBadge.demo.tsx` which demonstrates:

- All size variants
- All 17 supported vendors
- Icons enabled/disabled
- Clickable badges
- Unknown vendor fallback
- Custom styling

## Performance

- **Bundle Size**: ~8KB (minified, including all vendor configs)
- **Re-renders**: Optimized with React memoization (no unnecessary renders)
- **Accessibility**: WCAG AA compliant

## Browser Support

- Chrome/Edge: 90+
- Firefox: 88+
- Safari: 14.1+
- All browsers with ES2022 support

## License

Proprietary - SentriFlow

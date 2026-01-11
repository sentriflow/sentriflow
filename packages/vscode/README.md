# SentriFlow for VS Code

Validate network device configurations against security best practices and compliance rules in Visual Studio Code.

## What It Does

SentriFlow checks your network configurations (Cisco, Juniper, Arista, etc.) against defined compliance rules - either industry best practices or your company-specific policies. It's not a syntax checker; it validates that configurations meet security and operational standards.

## Features

- **Real-time compliance checks**: See policy violations as you type
- **Multi-vendor support**: Cisco, Juniper, Arista, Fortinet, Palo Alto, and more
- **Auto-detection**: Automatically detects vendor from configuration content
- **Customizable rules**: Use default best-practice rules or define company-specific policies
- **Rule management**: Enable/disable individual rules, vendors, or entire packs with 1-click
- **Visual configuration**: Activity Bar with TreeView and Settings panel for easy management
- **Rich hover tooltips**: Hover over diagnostics for detailed rule info, tags, and remediation
- **Category filtering**: Filter diagnostics by rule category
- **SARIF export**: Export results for CI/CD integration

## Activity Bar & Rules Panel

SentriFlow adds a dedicated icon to the VS Code Activity Bar for quick access to rule management.

### Rules TreeView

The hierarchical TreeView shows all rules organized by Pack, Vendor/Category, and optionally by Tag:

```
SENTRIFLOW RULES
├── sf-default (261 rules)
│   ├── cisco-ios (45 rules)
│   │   ├── Network-Segmentation
│   │   │   ├── ✓ NET-TRUNK-001 [warning]
│   │   │   └── ○ NET-ACCESS-001 (disabled)
│   │   └── Authentication
│   └── juniper-junos (38 rules)
├── acme-security (external pack)
│   └── arista-eos (8 rules)
│
└── By Tag (4 tags)
    ├── vlan-hopping (2 rules)        [security]
    │   └── JSON-CISCO-004
    ├── access-control (3 rules)      [security]
    ├── logging (2 rules)             [operational]
    └── cis-benchmark (1 rule)        [compliance]
```

**Tree Grouping Options**: Configure how rules are organized via Settings:
- `Vendor > Rules` (default)
- `Category > Rules`
- `Category > Vendor > Rules`
- `Vendor > Category > Rules`

**Tags Section**: Rules with typed tags are grouped in a dedicated "By Tag" section. Tags have types (`security`, `operational`, `compliance`, `general`) and rules with multiple tags appear under each. You can filter tags by type using the `sentriflow.tagTypeFilter` setting or the Command Palette.

**1-Click Toggle**: Click the toggle icon on any item to enable/disable:
- **Pack level**: Disables all rules in the pack
- **Vendor level**: Disables rules for that vendor within the pack
- **Rule level**: Disables the individual rule

**Context Menu Actions**:
- Right-click any item for toggle, copy, and view details options
- Copy Rule ID for use in settings or documentation

### IP Addresses Panel

The IP Addresses panel (between Rules and Settings) automatically extracts and displays all IP addresses and subnets from the current file:

```
IP ADDRESSES
├── IPv4 Addresses (5)
│   ├── 10.0.0.1
│   ├── 192.168.1.1
│   └── ...
├── IPv4 Subnets (3)
│   ├── 10.0.0.0/24
│   └── 192.168.0.0/16
└── IPv6 Addresses (2)
    └── 2001:db8::1
```

- **Click to Copy**: Click any IP address or subnet to copy it to clipboard
- **Copy All**: Use the clipboard button in the panel title to copy all IPs
- **Copy Category**: Each category (IPv4 Addresses, IPv4 Subnets, etc.) has its own copy button
- **Auto-Refresh**: Panel updates automatically when you switch files
- **Categorized**: IPs organized by type (IPv4/IPv6) and whether they're standalone addresses or subnets
- **Subnet Networks**: Network addresses from subnets (e.g., `10.0.0.0` from `10.0.0.0/24`) are included in the Addresses lists

### Settings Panel

The Settings panel provides a visual interface for all configuration options:

- Toggle switches for packs and vendors
- Disabled rules list with easy removal
- No JSON editing required

## Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "SentriFlow"
4. Click Install

Or install via command line:

```bash
code --install-extension sentriflow.sentriflow-vscode
```

## Supported File Types

The extension automatically activates for files with these extensions:

- `.conf`, `.cfg` - Generic configuration files
- `.ios`, `.junos` - Vendor-specific configurations
- `startup-config`, `running-config` - Cisco config filenames

## Configuration

### Extension Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `sentriflow.defaultVendor` | Vendor for parsing (`auto`, `cisco-ios`, `juniper-junos`, etc.) | `auto` |
| `sentriflow.showVendorInStatusBar` | Show detected vendor in status bar | `true` |
| `sentriflow.treeGrouping` | How to organize rules (`vendor`, `category`, `category-vendor`, `vendor-category`) | `vendor` |
| `sentriflow.showTagsSection` | Show "By Tag" section in tree view | `true` |
| `sentriflow.tagTypeFilter` | Filter tags by type (`all`, `security`, `operational`, `compliance`, `general`) | `all` |
| `sentriflow.enableDefaultRules` | Enable built-in default rules | `true` |
| `sentriflow.disabledRules` | List of rule IDs to disable globally | `[]` |
| `sentriflow.blockedPacks` | List of rule pack names to block | `[]` |
| `sentriflow.packVendorOverrides` | Per-pack vendor settings | `{}` |
| `sentriflow.encryptedPacks.enabled` | Enable loading of encrypted rule packs | `true` |
| `sentriflow.encryptedPacks.directory` | Directory for encrypted packs (leave empty for platform default) | `""` |
| `sentriflow.encryptedPacks.autoUpdate` | Auto-update behavior (`disabled`, `on-activation`, `daily`, `manual`) | `on-activation` |

### Disabling Individual Rules

**Using the GUI (Recommended)**:
1. Click the SentriFlow icon in the Activity Bar
2. Find the rule in the TreeView hierarchy
3. Click the toggle icon or right-click → "Toggle Enable/Disable"

**Using the Command Palette**:
- `SENTRIFLOW: Disable Rule...` - Fuzzy search to find and disable any rule
- `SENTRIFLOW: Enable Disabled Rule...` - Re-enable a previously disabled rule

**Using settings.json**:

```json
{
  "sentriflow.disabledRules": ["NET-SEC-001", "NET-DOC-001"]
}
```

You can also enter comma-separated values:

```json
{
  "sentriflow.disabledRules": ["NET-SEC-001,NET-DOC-001,CIS-VTY-002"]
}
```

### Disabling Rule Packs

**Using the GUI (Recommended)**:
1. Click the SentriFlow icon in the Activity Bar
2. Find the pack in the TreeView
3. Click the toggle icon to disable the entire pack

**Using the Command Palette**:
- `SENTRIFLOW: Enable/Disable Pack...` - Toggle entire rule packs
- `SENTRIFLOW: Enable/Disable Vendor...` - Toggle vendors within packs

**Using settings.json**:

To disable all default rules:

```json
{
  "sentriflow.enableDefaultRules": false
}
```

To block external rule packs from loading:

```json
{
  "sentriflow.blockedPacks": ["some-pack-name"]
}
```

### Example settings.json

```json
{
  "sentriflow.defaultVendor": "auto",
  "sentriflow.showVendorInStatusBar": true,
  "sentriflow.treeGrouping": "vendor-category",
  "sentriflow.showTagsSection": true,
  "sentriflow.enableDefaultRules": true,
  "sentriflow.disabledRules": ["NET-DOC-001", "NET-DOC-002"]
}
```

## Commands

### Scanning

| Command | Description |
|---------|-------------|
| `SENTRIFLOW: Scan Configuration` | Validate the current file |
| `SENTRIFLOW: Scan Selected Text` | Validate selected text only |

### Rule Management

| Command | Description |
|---------|-------------|
| `SENTRIFLOW: Disable Rule...` | Fuzzy search to disable any rule |
| `SENTRIFLOW: Enable Disabled Rule...` | Re-enable a disabled rule |
| `SENTRIFLOW: Enable/Disable Pack...` | Toggle entire rule packs |
| `SENTRIFLOW: Enable/Disable Vendor...` | Toggle vendors within packs |
| `SENTRIFLOW: Show All Disabled Items` | View summary of disabled packs/vendors/rules |
| `SENTRIFLOW: Show Rules Panel` | Focus the Rules TreeView |
| `SENTRIFLOW: Show Rule Packs` | Legacy menu for rule pack management |
| `SENTRIFLOW: Filter Diagnostics by Category` | Filter displayed diagnostics by rule category |
| `SENTRIFLOW: Filter Tags by Type...` | Filter the "By Tag" section by tag type |

### Configuration

| Command | Description |
|---------|-------------|
| `SENTRIFLOW: Select Vendor` | Choose vendor for parsing |
| `SENTRIFLOW: Set as Network Config` | Set file language to network-config |
| `SENTRIFLOW: Toggle Debug Logging` | Enable/disable debug output |

## Hover Tooltips

Hover over any diagnostic (squiggly underline) to see detailed information:

- **Rule ID and Category**: Quick identification and grouping
- **Tags**: All typed tags with their type (`security`, `operational`, `compliance`, `general`) and optional scores
- **Description**: Full explanation of the compliance issue
- **Remediation**: Specific guidance on how to fix the issue
- **Owner Info**: OBU and owner details for internal rules

The diagnostic messages also include the rule ID and category in brackets for quick reference:
```
[NET-SEC-001] (authentication) Plaintext password detected in configuration
```

## Status Bar

The extension shows three status bar items:

1. **SENTRIFLOW** - Scan status with error/warning counts (hover for details with quick action links)
2. **Vendor** - Detected or configured vendor (click to change, hover for pack info)
3. **Rules** - Active rule count (click to manage, hover shows disabled count)

**Rich Tooltips**: Hover over any status bar item for detailed information with clickable links to common actions.

## Custom JSON Rules

Create organization-specific validation rules without writing TypeScript. Custom rules are stored in `.sentriflow/rules/*.json` files in your workspace.

### Quick Start

1. Open Command Palette (`Ctrl+Shift+P`)
2. Run `SENTRIFLOW: Create Custom Rules File`
3. Edit the generated file with your rules

### Example Rule

```json
{
  "version": "1.0",
  "rules": [
    {
      "id": "ACME-TRUNK-001",
      "selector": "interface",
      "vendor": "cisco-ios",
      "metadata": {
        "level": "warning",
        "obu": "Network Engineering",
        "owner": "NetOps",
        "description": "Trunk ports should have explicit allowed VLAN list",
        "remediation": "Add 'switchport trunk allowed vlan <list>'"
      },
      "check": {
        "type": "and",
        "conditions": [
          { "type": "helper", "helper": "cisco.isTrunkPort", "args": [{ "$ref": "node" }] },
          { "type": "helper", "helper": "isShutdown", "args": [{ "$ref": "node" }], "negate": true },
          { "type": "child_not_exists", "selector": "switchport trunk allowed vlan" }
        ]
      }
    }
  ]
}
```

### Features

- **IntelliSense**: Auto-completion for vendors, check types, and helper functions
- **Live Reload**: Rules apply immediately when you save the file
- **Validation**: JSON schema validation catches errors as you type
- **Priority**: Custom rules override built-in rules with the same ID

### Commands

| Command | Description |
|---------|-------------|
| `SENTRIFLOW: Create Custom Rules File` | Create a new rules file with example |
| `SENTRIFLOW: Copy Rule to Custom` | Copy any rule to your custom file (right-click menu) |
| `SENTRIFLOW: Edit Custom Rule` | Jump to rule definition in JSON file |
| `SENTRIFLOW: Delete Custom Rule` | Remove a custom rule |

### Documentation

See the **[Rule Authoring Guide](https://github.com/sentriflow/sentriflow/blob/main/docs/RULE_AUTHORING_GUIDE.md)** for complete documentation including:

- All check types (`match`, `child_exists`, `helper`, `expr`, etc.)
- Logical combinators (`and`, `or`, `not`)
- Helper function reference (vendor-specific and common)
- Security metadata and tagging

## Extension API

External extensions can register rule packs programmatically:

```typescript
const sentriflow = vscode.extensions.getExtension('sentriflow.sentriflow-vscode');
const api = sentriflow?.exports;

api?.registerRulePack({
  name: 'my-rules',
  version: '1.0.0',
  publisher: 'My Company',
  priority: 100,
  rules: [/* IRule objects */],
});
```

## Cloud Licensing (Commercial)

SentriFlow supports cloud-based rule pack distribution for commercial customers. This enables automatic updates and access to premium rule packs.

### License Panel

The License panel in the Activity Bar shows:
- **License Status**: Active, expiring soon, or expired
- **Cloud Connection**: Online or offline (with cache time remaining)
- **Tier**: Community, Professional, or Enterprise
- **Entitled Feeds**: Which rule packs your license includes
- **Loaded Packs**: Currently loaded rule packs with rule counts

### License Commands

| Command | Description |
|---------|-------------|
| `SENTRIFLOW: Enter License Key` | Enter or update your license key |
| `SENTRIFLOW: Clear License Key` | Remove stored license key |
| `SENTRIFLOW: Show License Status` | View license details and options |
| `SENTRIFLOW: Check for Updates` | Check for rule pack updates |
| `SENTRIFLOW: Download Updates` | Download available pack updates |
| `SENTRIFLOW: Reload Packs` | Reload all encrypted rule packs |

### Offline Mode

SentriFlow supports offline operation with a 72-hour grace period:

- **Entitlement Caching**: Entitlements are cached locally for 72 hours
- **Graceful Degradation**: When offline, cached entitlements are used automatically
- **Status Indicator**: The License panel shows connection status and cache time remaining
- **Cached Packs**: Previously downloaded packs work offline indefinitely

### Getting a License

Visit [sentriflow.com.au/pricing](https://sentriflow.com.au/pricing) or click "Get License" in the License panel.

## Architecture Notes

### GRX2 Loader

The GRX2 encrypted pack loader implementation lives in `@sentriflow/core/grx2-loader`. The VS Code extension re-exports these functions for internal use. This shared implementation ensures consistent behavior between CLI and VS Code when loading encrypted rule packs.

See the [Core package documentation](https://github.com/sentriflow/sentriflow/tree/main/packages/core#grx2-loader-module) for API details.

## Related

- [SentriFlow CLI](https://github.com/sentriflow/sentriflow/tree/main/packages/cli)
- [SentriFlow Core](https://github.com/sentriflow/sentriflow/tree/main/packages/core)

## Privacy & Data Collection

SentriFlow is designed with privacy in mind:

### Open Source Features (Free)

- **No data collection**: The open-source extension collects no telemetry or usage data
- **Local processing**: All configuration scanning happens locally on your machine
- **No network calls**: No data is transmitted to external servers

### Commercial Features (Encrypted Packs)

When using commercial encrypted rule packs, the following applies:

| Data | Purpose | Storage |
|------|---------|---------|
| Hardware ID | License binding to prevent sharing | Local only (VS Code secrets) |
| License key | Authentication with update server | Local only (VS Code secrets) |
| API requests | Check for pack updates | Transmitted to SentriFlow API |

**Important Notes**:

- Hardware ID is a hash that cannot identify you personally
- Data collection only occurs when you explicitly enter a license key
- You can clear all stored data via "SENTRIFLOW: Clear License Key" command
- See our [Privacy Policy](https://sentriflow.com.au/privacy) for complete details

### Opt-Out

Commercial features are disabled by default. To ensure no data collection:

1. Don't enter a license key
2. Or set `sentriflow.encryptedPacks.enabled` to `false`

## License

Apache-2.0

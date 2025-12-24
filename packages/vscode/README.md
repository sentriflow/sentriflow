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
- **SARIF export**: Export results for CI/CD integration

## Activity Bar & Rules Panel

SentriFlow adds a dedicated icon to the VS Code Activity Bar for quick access to rule management.

### Rules TreeView

The hierarchical TreeView shows all rules organized by:

```
SENTRIFLOW RULES
├── [Pack: sf-essentials] (78 rules)
│   ├── [Vendor: cisco-ios] (12 rules)
│   │   ├── ✓ NET-TRUNK-001 [warning]
│   │   └── ○ NET-ACCESS-001 (disabled)
│   └── [Vendor: juniper-junos] (10 rules)
└── [Pack: acme-security] (external pack)
    └── [Vendor: arista-eos] (8 rules)
```

**1-Click Toggle**: Click the toggle icon on any item to enable/disable:
- **Pack level**: Disables all rules in the pack
- **Vendor level**: Disables rules for that vendor within the pack
- **Rule level**: Disables the individual rule

**Context Menu Actions**:
- Right-click any item for toggle, copy, and view details options
- Copy Rule ID for use in settings or documentation

### Settings Panel

The Settings panel (below Rules in the sidebar) provides a visual interface for all configuration options:

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
| `sentriflow.enableDefaultRules` | Enable built-in default rules | `true` |
| `sentriflow.disabledRules` | List of rule IDs to disable globally | `[]` |
| `sentriflow.blockedPacks` | List of rule pack names to block | `[]` |
| `sentriflow.packVendorOverrides` | Per-pack vendor settings | `{}` |

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

### Configuration

| Command | Description |
|---------|-------------|
| `SENTRIFLOW: Select Vendor` | Choose vendor for parsing |
| `SENTRIFLOW: Set as Network Config` | Set file language to network-config |
| `SENTRIFLOW: Toggle Debug Logging` | Enable/disable debug output |

## Status Bar

The extension shows three status bar items:

1. **SENTRIFLOW** - Scan status with error/warning counts (hover for details with quick action links)
2. **Vendor** - Detected or configured vendor (click to change, hover for pack info)
3. **Rules** - Active rule count (click to manage, hover shows disabled count)

**Rich Tooltips**: Hover over any status bar item for detailed information with clickable links to common actions.

## Custom Rules

External extensions can register rule packs via the SentriFlow API:

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

See the [Rule Authoring Guide](https://github.com/sentriflow/sentriflow/blob/main/docs/RULE_AUTHORING_GUIDE.md) for details.

## Related

- [SentriFlow CLI](https://github.com/sentriflow/sentriflow/tree/main/packages/cli)
- [SentriFlow Core](https://github.com/sentriflow/sentriflow/tree/main/packages/core)

## License

Apache-2.0

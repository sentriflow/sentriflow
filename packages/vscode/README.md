# SentriFlow for VS Code

Validate network device configurations against security best practices and compliance rules in Visual Studio Code.

## What It Does

SentriFlow checks your network configurations (Cisco, Juniper, Arista, etc.) against defined compliance rules - either industry best practices or your company-specific policies. It's not a syntax checker; it validates that configurations meet security and operational standards.

## Features

- **Real-time compliance checks**: See policy violations as you type
- **Multi-vendor support**: Cisco, Juniper, Arista, Fortinet, Palo Alto, and more
- **Auto-detection**: Automatically detects vendor from configuration content
- **Customizable rules**: Use default best-practice rules or define company-specific policies
- **Rule management**: Enable/disable individual rules or entire rule packs
- **SARIF export**: Export results for CI/CD integration

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

Add rule IDs to `sentriflow.disabledRules` in your settings:

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

Or use the UI: **SENTRIFLOW: Show Rule Packs** → Select pack → **View All Rules** → Select rule → **Disable Rule**

### Disabling Rule Packs

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

| Command | Description |
|---------|-------------|
| `SENTRIFLOW: Scan Configuration` | Validate the current file |
| `SENTRIFLOW: Scan Selected Text` | Validate selected text only |
| `SENTRIFLOW: Select Vendor` | Choose vendor for parsing |
| `SENTRIFLOW: Show Rule Packs` | View and manage rule packs |
| `SENTRIFLOW: Set as Network Config` | Set file language to network-config |
| `SENTRIFLOW: Toggle Debug Logging` | Enable/disable debug output |

## Status Bar

The extension shows three status bar items:

1. **SENTRIFLOW** - Scan status with error/warning counts
2. **Vendor** - Detected or configured vendor (click to change)
3. **Rules** - Active rule count (click to manage packs)

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

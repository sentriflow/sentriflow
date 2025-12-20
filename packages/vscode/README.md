# SentriFlow for VS Code

Real-time network configuration linting and validation in Visual Studio Code.

## Features

- **Real-time validation**: See issues as you type
- **Multi-vendor support**: Cisco, Juniper, Arista, Fortinet, Palo Alto, and more
- **Quick fixes**: Automated suggestions for common issues
- **Hover information**: Detailed explanations for configuration blocks
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

- `.conf`, `.config` - Generic configuration files
- `.ios`, `.iosxe`, `.nxos` - Cisco configurations
- `.junos` - Juniper configurations
- `.eos` - Arista configurations
- `.fortigate` - Fortinet configurations
- `.panos` - Palo Alto configurations

## Configuration

### Extension Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `sentriflow.severity` | Minimum severity to display | `warning` |
| `sentriflow.autoDetect` | Auto-detect vendor from content | `true` |
| `sentriflow.validateOnSave` | Validate on file save | `true` |
| `sentriflow.validateOnType` | Validate while typing | `true` |

### Example settings.json

```json
{
  "sentriflow.severity": "info",
  "sentriflow.autoDetect": true,
  "sentriflow.validateOnSave": true
}
```

## Custom Rules

You can extend SentriFlow with custom rule packs. See the [templates](https://github.com/sentriflow/sentriflow/tree/main/templates) for creating your own rules.

## Commands

| Command | Description |
|---------|-------------|
| `SentriFlow: Validate Document` | Validate the current file |
| `SentriFlow: Export SARIF` | Export results to SARIF file |
| `SentriFlow: Clear Diagnostics` | Clear all validation markers |

## Screenshots

![SentriFlow in action](https://github.com/sentriflow/sentriflow/raw/main/docs/images/vscode-demo.png)

## Related

- [SentriFlow CLI](https://github.com/sentriflow/sentriflow/tree/main/packages/cli)
- [SentriFlow Core](https://github.com/sentriflow/sentriflow/tree/main/packages/core)

## License

Apache-2.0

# SentriFlow

Network configuration compliance validation for Cisco, Juniper, Arista, and more.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

SentriFlow is an open-source compliance validator for network device configurations. It checks configurations against security best practices and policy rules - either industry standards or your company-specific requirements. It supports multiple network vendors and can be used via CLI or VS Code extension.

## Packages

### [@sentriflow/core](./packages/core)

Core engine providing AST-based parsing and validation. Converts configurations into a vendor-agnostic Abstract Syntax Tree and runs rules against it. Includes vendor-specific helper functions for writing validation rules (utilities for extracting interfaces, ACLs, VTY lines, and common configuration patterns). Full TypeScript support.

### [@sentriflow/cli](./packages/cli)

Command-line interface for scanning configuration files. Supports JSON and SARIF output formats. Integrates with GitHub Actions and CI/CD pipelines.

### [@sentriflow/rules-default](./packages/rules-default)

Starter set of example rules covering security (SEC-XXX), network (NET-XXX), and compliance (CMP-XXX) patterns. Use as a reference for writing your own rules.

### [sentriflow-vscode](./packages/vscode)

VS Code extension for real-time compliance validation. Checks configurations against best practices and custom policies as you type. Multi-vendor support and SARIF export for CI/CD.

## Supported Vendors

- Cisco IOS/IOS-XE/NX-OS
- Juniper JunOS
- Arista EOS
- Aruba AOS-CX/AOS-Switch
- Fortinet FortiOS
- Palo Alto PAN-OS
- Nokia SR OS
- Huawei VRP
- Cumulus Linux
- VyOS
- MikroTik RouterOS
- Extreme EXOS

## Documentation

- **[Rule Authoring Guide](docs/RULE_AUTHORING_GUIDE.md)** - Complete guide for writing custom JSON and TypeScript validation rules

## Quick Start

### CLI Installation

**Requirements:** Node.js 18+ or Bun 1.0+

```bash
# Using npm
npm install -g @sentriflow/cli

# Using bun
bun add -g @sentriflow/cli
```

### CLI Usage

```bash
# Scan a configuration file
sentriflow router.conf

# Scan with specific vendor
sentriflow -v cisco-ios switch.conf

# Scan a directory recursively
sentriflow -D configs/ -R

# Output as SARIF (for CI/CD)
sentriflow router.conf -f sarif
```

### VS Code Extension

Search for "SentriFlow" in the VS Code Extensions marketplace, or install from the command line:

```bash
code --install-extension sentriflow.sentriflow-vscode
```

## Programmatic Usage

```typescript
import { parse, lint } from '@sentriflow/core';
import { defaultRules } from '@sentriflow/rules-default';

const config = `
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
`;

const ast = parse(config, { vendor: 'cisco-ios' });
const results = lint(ast, defaultRules);

console.log(results);
```

## Writing Custom Rules

SentriFlow supports two formats for custom rules:

- **JSON Rules** - Portable, shareable, sandboxed execution (recommended for most users)
- **TypeScript Rules** - Full programming flexibility for complex logic

See the **[Rule Authoring Guide](docs/RULE_AUTHORING_GUIDE.md)** for complete documentation including:

- Quick start examples
- Understanding the configuration AST
- All available check types and operators
- Helper function reference by vendor
- Best practices and troubleshooting

### Quick Example (JSON)

```json
{
  "id": "MY-001",
  "selector": "interface",
  "vendor": "cisco-ios",
  "metadata": { "level": "warning", "obu": "NetOps", "owner": "Team" },
  "check": {
    "type": "child_not_exists",
    "selector": "description"
  },
  "failureMessage": "Interface {nodeId} missing description"
}
```

### Quick Example (TypeScript)

```typescript
import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import { hasChildCommand } from '@sentriflow/core';

export const myRule: IRule = {
  id: 'MY-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  metadata: { level: 'warning', obu: 'NetOps', owner: 'Team' },
  check: (node: ConfigNode): RuleResult => ({
    passed: hasChildCommand(node, 'description'),
    message: hasChildCommand(node, 'description')
      ? 'Has description'
      : `Interface ${node.id} missing description`,
    ruleId: 'MY-001',
    nodeId: node.id,
    level: 'warning',
    loc: node.loc,
  }),
};
```

## Development

### Prerequisites

- [Bun](https://bun.sh/) v1.0 or later

```bash
# Install Bun (macOS, Linux, WSL)
curl -fsSL https://bun.sh/install | bash
```

### Setup

```bash
# Clone the repository
git clone https://github.com/sentriflow/sentriflow.git
cd sentriflow

# Install dependencies
bun install
```

### Common Commands

```bash
# Run type checking
bun run type-check

# Run tests
bun test

# Build CLI (for npm publish)
cd packages/cli && bun run build

# Build standalone CLI executable
bun run build:cli
```

### Building VS Code Extension

```bash
# Navigate to vscode package
cd packages/vscode

# Production build (minified)
bun run build

# Development build (with source maps)
bun run build:dev

# Watch mode (auto-rebuild on changes)
bun run watch

# Create .vsix package
bun run package
```

### Installing VS Code Extension Locally

After building, install the `.vsix` file:

```bash
# From command line
code --install-extension packages/vscode/sentriflow-vscode-*.vsix

# Or in VS Code:
# 1. Open Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
# 2. Run "Extensions: Install from VSIX..."
# 3. Select the .vsix file from packages/vscode/
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Apache 2.0 - see [LICENSE](LICENSE) for details.

## Commercial Extensions

For enterprise features including encrypted rule packs, premium rules, and support, visit [sentriflow.com.au](https://sentriflow.com.au).

## Business Model: Open Core

SentriFlow uses an **Open Core** model. The core scanning engine, CLI, VS Code extension, and default rules are fully open source under Apache-2.0. Commercial extensions provide premium content and enterprise features.

| Feature                                      | OSS (Apache-2.0) | Commercial |
| -------------------------------------------- | :--------------: | :--------: |
| Core scanning engine                         |        ✅        |     ✅     |
| Default rules (Cisco, Juniper, Arista, etc.) |        ✅        |     ✅     |
| CLI & VS Code extension                      |        ✅        |     ✅     |
| Local custom rules (JSON/TypeScript)         |        ✅        |     ✅     |
| Encrypted rule packs (.grpx)                 |    ✅ (local)    |     ✅     |
| Premium vendor-specific rules                |        ❌        |     ✅     |
| Cloud-based pack updates                     |        ❌        |     ✅     |
| Online license management                    |        ❌        |     ✅     |
| Enterprise support                           |        ❌        |     ✅     |

The OSS version is fully functional for security scanning. Commercial features provide premium content and convenience, not core functionality.

### Extensibility: Pack Providers

The core exposes an `IPackProvider` interface for loading rule packs from custom sources:

```typescript
import { setPackProvider, IPackProvider, RulePack } from '@sentriflow/core';

class MyPackProvider implements IPackProvider {
  async loadPacks(): Promise<RulePack[]> {
    // Load packs from your custom source
    return [];
  }
}

setPackProvider(new MyPackProvider());
```

This enables:

- Community-built pack sources (Git repos, internal APIs, etc.)
- Private enterprise integrations
- The optional `@sentriflow/licensing` commercial package

See [LICENSING.md](LICENSING.md) for detailed licensing information.

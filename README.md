# SentriFlow

**Policy validation for network device configurations.**

**[Documentation](https://docs.sentriflow.com.au)** | **[Rule Packs](https://www.sentriflow.com.au/#pricing)**

---

## What is SentriFlow?

SentriFlow is an open-source validation tool for network device configurations. It checks configurations against security best practices and policy rules — either industry standards or your company-specific requirements.

**Example:** Given this Cisco IOS configuration with security gaps:

```text
hostname R1
!
interface GigabitEthernet0/0           ← No description (undocumented)
  ip address 192.168.1.1 255.255.255.0
!
line vty 0 4                           ← No access-class (unrestricted access)
  transport input ssh
```

**SentriFlow identifies the issues:**

```json
{
  "results": [
    {
      "ruleId": "NET-DOC-001",
      "level": "warning",
      "message": "Interface \"GigabitEthernet0/0\" is missing a description.",
      "loc": { "startLine": 3 }
    },
    {
      "ruleId": "JSON-CISCO-005",
      "level": "error",
      "message": "VTY line vty 0 4 is missing access-class for SSH access control",
      "loc": { "startLine": 6 },
      "remediation": "Add 'access-class <acl> in' to restrict VTY access"
    }
  ]
}
```

*Output formats: JSON (default), human-readable for terminal, or SARIF for CI/CD integration.*

**Use cases:**
- Pre-deployment validation in CI/CD pipelines
- Security audits and compliance checks
- Configuration drift detection
- Enforcing organizational standards

> **Note**: SentriFlow is a configuration validation tool that assesses alignment with security standards and policies. It provides technical control assessments but does not certify compliance with regulatory frameworks. Final compliance certification is the responsibility of qualified auditors.

---

## Quick Start

```bash
# Install
npm install -g @sentriflow/cli

# Validate a config file (JSON output, default)
sentriflow router.conf

# Human-readable output for terminal
sentriflow -f human router.conf
# Output:
#   /path/to/router.conf
#     3:1   warning  Interface "GigabitEthernet0/0" is missing a description.  NET-DOC-001
#     6:1   error    VTY line vty 0 4 is missing access-class for SSH access   JSON-CISCO-005
#
#   ✖ 2 problems (1 error, 1 warning)
#
# Format: <line>:<column>  <severity>  <message>  <rule-id>

# Validate with specific vendor
sentriflow -v cisco-ios switch.conf

# Output as SARIF (for GitHub Advanced Security)
sentriflow -f sarif router.conf
```

**VS Code Extension:** Search "SentriFlow" in the marketplace for real-time validation as you edit.

---

## Supported Vendors

| Vendor | Platforms |
|--------|-----------|
| Cisco | IOS, IOS-XE, NX-OS, ASA |
| Juniper | JunOS |
| Arista | EOS |
| Palo Alto | PAN-OS |
| Fortinet | FortiOS |
| Aruba | AOS-CX, AOS-Switch |
| Nokia | SR OS |
| Huawei | VRP |
| MikroTik | RouterOS |
| VyOS | VyOS |
| Cumulus | Linux |
| Extreme | EXOS |

---

## Packages

| Package | Description |
|---------|-------------|
| [@sentriflow/core](packages/core) | Parsing engine and rule runtime. Zero dependencies. |
| [@sentriflow/cli](packages/cli) | Command-line interface with JSON/SARIF output. |
| [@sentriflow/rules-default](packages/rules-default) | Example rules demonstrating the rule format (3-4 per vendor). |
| [sentriflow-vscode](packages/vscode) | VS Code extension for real-time validation. |

> **Note:** `rules-default` contains example rules to demonstrate capabilities. For production security baselines, see [SentriFlow Rule Packs](https://www.sentriflow.com.au/#pricing).

---

## Programmatic Usage

```typescript
import { SchemaAwareParser, RuleEngine } from '@sentriflow/core';
import { allRules } from '@sentriflow/rules-default';

const config = `
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
`;

const parser = new SchemaAwareParser();
const nodes = parser.parse(config);

const engine = new RuleEngine();
const results = engine.run(nodes, allRules);

console.log(results);
```

---

## Writing Custom Rules

SentriFlow supports **JSON rules** (portable, sandboxed) and **TypeScript rules** (full flexibility).

### JSON Example

```json
{
  "id": "CORP-001",
  "selector": "interface",
  "vendor": "cisco-ios",
  "metadata": {
    "level": "warning",
    "obu": "NetOps",
    "owner": "Team",
    "tags": [{ "type": "operational", "label": "documentation" }]
  },
  "check": {
    "type": "child_not_exists",
    "selector": "description"
  },
  "failureMessage": "Interface {nodeId} missing description"
}
```

### TypeScript Example

```typescript
import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import { hasChildCommand } from '@sentriflow/core';

export const interfaceDescription: IRule = {
  id: 'CORP-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  metadata: { level: 'warning', obu: 'NetOps', owner: 'Team' },
  check: (node: ConfigNode): RuleResult => ({
    passed: hasChildCommand(node, 'description'),
    message: hasChildCommand(node, 'description')
      ? 'Has description'
      : `Interface ${node.id} missing description`,
  }),
};
```

See the **[Rule Authoring Guide](docs/RULE_AUTHORING_GUIDE.md)** for complete documentation.

---

## Open Core Model

SentriFlow uses an **open core** model. The engine, CLI, VS Code extension, and example rules are fully open source (Apache-2.0). Commercial rule packs provide production-ready content.

| Feature | Open Source | Commercial |
|---------|:-----------:|:----------:|
| Core scanning engine | ✅ | ✅ |
| CLI & VS Code extension | ✅ | ✅ |
| Example rules | ✅ | ✅ |
| Custom rule authoring | ✅ | ✅ |
| Security baseline rules (200+) | ❌ | ✅ |
| Compliance-mapped rules (CIS, PCI-DSS, NIST) | ❌ | ✅ |
| Vendor deep-dive packs | ❌ | ✅ |
| Quarterly rule updates | ❌ | ✅ |
| Priority support | ❌ | ✅ |

**[View Rule Packs →](https://www.sentriflow.com.au/#pricing)**

---

## Using Rule Packs

```bash
# Load encrypted rule pack (requires license)
sentriflow --pack security-baseline.grx2 --license-key $KEY router.conf

# Mix packs and custom rules
sentriflow --pack baseline.grx2 --pack custom.js --license-key $KEY configs/
```

Packs work fully offline. License validates once at activation.

---

## Development

### Prerequisites

- [Bun](https://bun.sh/) v1.0+ (or Node.js 18+)

### Setup

```bash
git clone https://github.com/sentriflow/sentriflow.git
cd sentriflow
bun install
```

### Commands

```bash
bun run type-check    # Type checking
bun test              # Run tests
bun run build:cli     # Build standalone CLI
```

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

---

## Community

- [GitHub Issues](https://github.com/sentriflow/sentriflow/issues) — Bug reports and feature requests
- [Documentation](https://docs.sentriflow.com.au) — Guides and API reference
- [Changelog](CHANGELOG.md) — Release history

---

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <a href="https://sentriflow.com.au">sentriflow.com.au</a> ·
  <a href="https://docs.sentriflow.com.au">Documentation</a> ·
  <a href="https://www.sentriflow.com.au/#pricing">Rule Packs</a>
</p>

# @sentriflow/core

Core engine for SentriFlow - a network configuration compliance validator.

## Overview

`@sentriflow/core` provides the fundamental building blocks for parsing and analyzing network device configurations across multiple vendors, checking them against compliance rules—whether industry best practices or your organization's specific requirements.

## Installation

```bash
npm install @sentriflow/core
# or
bun add @sentriflow/core
```

## Features

- **Multi-vendor support**: Cisco IOS/NX-OS, Juniper JunOS, Arista EOS, Fortinet FortiGate, Palo Alto PAN-OS, and more
- **AST-based parsing**: Converts configurations into a vendor-agnostic Abstract Syntax Tree
- **Extensible rule engine**: Define compliance rules for best practices or organization-specific policies
- **IP/Subnet Extraction**: Extract and deduplicate IP addresses and CIDR subnets from configurations
- **TypeScript native**: Full type safety with comprehensive type definitions

## Supported Vendors

| Vendor | Platform | Status |
|--------|----------|--------|
| Cisco | IOS, IOS-XE, NX-OS | Supported |
| Juniper | JunOS | Supported |
| Arista | EOS | Supported |
| Fortinet | FortiGate | Supported |
| Palo Alto | PAN-OS | Supported |
| Nokia | SR-OS | Supported |
| Huawei | VRP | Supported |
| MikroTik | RouterOS | Supported |
| Cumulus | Linux | Supported |
| VyOS | VyOS | Supported |
| Extreme | EXOS | Supported |
| Aruba | AOS-CX | Supported |

## Basic Usage

```typescript
import { parse, validate } from '@sentriflow/core';
import { defaultRules } from '@sentriflow/rules-default';

// Parse a configuration file
const config = `
interface GigabitEthernet0/1
  ip address 192.168.1.1 255.255.255.0
  no shutdown
`;

const ast = parse(config, { vendor: 'cisco-ios' });

// Check compliance against rules
const results = validate(ast, defaultRules);

for (const issue of results) {
  console.log(`${issue.severity}: ${issue.message}`);
}
```

## API Reference

### `parse(config: string, options: ParseOptions): AST`

Parses a network configuration string into an AST.

### `validate(ast: AST, rules: Rule[]): ValidationResult[]`

Checks an AST for compliance against a set of rules.

### `detect(config: string): VendorInfo | null`

Auto-detects the vendor/platform from configuration content.

### `extractIPSummary(content: string, options?: ExtractOptions): IPSummary`

Extracts all IP addresses and subnets from configuration text.

```typescript
import { extractIPSummary } from '@sentriflow/core';

const config = `
interface GigabitEthernet0/1
  ip address 192.168.1.1 255.255.255.0
  ip route 10.0.0.0/24 via 192.168.1.254
`;

const summary = extractIPSummary(config);
// {
//   ipv4Addresses: ['192.168.1.1', '192.168.1.254'],
//   ipv6Addresses: [],
//   ipv4Subnets: ['10.0.0.0/24'],
//   ipv6Subnets: [],
//   counts: { total: 3, ipv4: 2, ipv6: 0, ipv4Subnets: 1, ipv6Subnets: 0 }
// }
```

**Options:**
- `maxContentSize`: Maximum input size in bytes (default: 50MB) - prevents DoS
- `includeSubnetNetworks`: Include subnet network addresses in address lists
- `skipIPv4`, `skipIPv6`, `skipSubnets`: Skip specific extraction types

## Related Packages

- [`@sentriflow/cli`](https://github.com/sentriflow/sentriflow/tree/main/packages/cli) - Command-line interface
- [`@sentriflow/rules-default`](https://github.com/sentriflow/sentriflow/tree/main/packages/rules-default) - Default compliance rules
- [`@sentriflow/rule-helpers`](https://github.com/sentriflow/sentriflow/tree/main/packages/rule-helpers) - Helper functions for rule development

## License

Apache-2.0

# @sentriflow/core

Core engine for SentriFlow - a network configuration validator.

## Overview

`@sentriflow/core` provides the fundamental building blocks for parsing and analyzing network device configurations across multiple vendors, validating them against policy rules—whether industry best practices or your organization's specific requirements.

SentriFlow is a validation tool that assesses configuration alignment with policies and standards.

## Installation

```bash
npm install @sentriflow/core
# or
bun add @sentriflow/core
```

## Features

- **Multi-vendor support**: Cisco IOS/NX-OS, Juniper JunOS, Arista EOS, Fortinet FortiGate, Palo Alto PAN-OS, and more
- **AST-based parsing**: Converts configurations into a vendor-agnostic Abstract Syntax Tree
- **Extensible rule engine**: Define validation rules for best practices or organization-specific policies
- **IP/Subnet Extraction**: Extract and deduplicate IP addresses and CIDR subnets from configurations
- **GRX2 Loader**: Load and decrypt extended encrypted rule packs for offline usage
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

## GRX2 Loader Module

The `grx2-loader` module provides functionality for loading extended encrypted rule packs (.grx2). These packs embed wrapped encryption keys, enabling offline scanning without network access.

### Exported Functions

```typescript
import {
  loadExtendedPack,
  loadAllPacks,
  getPackInfo,
  getMachineId,
  getMachineIdSync,
  isExtendedGRX2,
} from '@sentriflow/core/grx2-loader';
```

| Function | Description |
|----------|-------------|
| `loadExtendedPack(filePath, licenseKey, machineId?)` | Load and decrypt a single GRX2 pack |
| `loadAllPacks(directory, licenseKey, machineId?)` | Load all GRX2 packs from a directory |
| `getPackInfo(filePath)` | Get metadata from a pack without decrypting |
| `getMachineId()` | Get the current machine identifier (async) |
| `getMachineIdSync()` | Get the current machine identifier (sync) |
| `isExtendedGRX2(buffer)` | Check if a buffer contains an extended GRX2 pack |

### Types

```typescript
import type {
  GRX2ExtendedHeader,
  GRX2PackLoadResult,
  EncryptedPackInfo,
  EncryptedPackErrorCode,
  LicensePayload,
} from '@sentriflow/core/grx2-loader';

import { EncryptedPackError } from '@sentriflow/core/grx2-loader';
```

### Example Usage

```typescript
import { loadExtendedPack, getMachineId } from '@sentriflow/core/grx2-loader';

const licenseKey = process.env.SENTRIFLOW_LICENSE_KEY;
const machineId = await getMachineId();

try {
  const result = await loadExtendedPack('./rules.grx2', licenseKey, machineId);
  if (result.success) {
    console.log(`Loaded ${result.totalRules} rules`);
  }
} catch (error) {
  if (error instanceof EncryptedPackError) {
    console.error(`Pack error: ${error.code} - ${error.message}`);
  }
}
```

### Machine-Bound vs Portable Packs

- **Portable packs**: Pass empty string for `machineId` parameter
- **Machine-bound packs**: Pass the result of `getMachineId()` for device-specific binding

## Related Packages

- [`@sentriflow/cli`](https://github.com/sentriflow/sentriflow/tree/main/packages/cli) - Command-line interface
- [`@sentriflow/rules-default`](https://github.com/sentriflow/sentriflow/tree/main/packages/rules-default) - Default validation rules
- [`@sentriflow/rule-helpers`](https://github.com/sentriflow/sentriflow/tree/main/packages/rule-helpers) - Helper functions for rule development

## Disclaimer

SentriFlow provides automated configuration validation. Validation results do not constitute compliance certification.

## License

Apache-2.0

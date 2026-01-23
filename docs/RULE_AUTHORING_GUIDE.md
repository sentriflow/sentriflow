# SentriFlow Rule Authoring Guide

This guide walks you through creating custom validation rules for SentriFlow, from simple checks to complex multi-condition validations.

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Understanding the AST](#understanding-the-ast)
4. [JSON Rules Guide](#json-rules-guide)
5. [TypeScript Rules Guide](#typescript-rules-guide)
6. [Helper Functions Reference](#helper-functions-reference)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Introduction

### What are SentriFlow Rules?

SentriFlow rules are validation checks that run against parsed network device configurations. Each rule inspects specific configuration elements and reports whether they align with your security policies and best practices.

### JSON vs TypeScript: When to Use Each

| Use JSON Rules When... | Use TypeScript Rules When... |
|------------------------|------------------------------|
| You need portable, shareable rules | You need complex logic or loops |
| Non-developers will author rules | You want full IDE support |
| Rules should work without compilation | You need custom helper functions |
| You want sandboxed, safe execution | You need access to external data |

**Recommendation:** Start with JSON rules for most use cases. Move to TypeScript when you hit JSON's limitations.

### Prerequisites

- Node.js 18+ or Bun 1.0+
- Basic understanding of network device configurations
- For TypeScript rules: familiarity with TypeScript

---

## Quick Start

### Your First JSON Rule

Create a file `my-rules.json`:

```json
{
  "version": "1.0",
  "meta": {
    "name": "My Custom Rules",
    "author": "Your Name"
  },
  "rules": [
    {
      "id": "MY-001",
      "selector": "interface",
      "vendor": "cisco-ios",
      "metadata": {
        "level": "warning",
        "obu": "Network Team",
        "owner": "NetOps",
        "description": "Interfaces should have descriptions"
      },
      "check": {
        "type": "and",
        "conditions": [
          {
            "type": "helper",
            "helper": "cisco.isPhysicalPort",
            "args": [{ "$ref": "node.id" }]
          },
          {
            "type": "helper",
            "helper": "isShutdown",
            "args": [{ "$ref": "node" }],
            "negate": true
          },
          {
            "type": "child_not_exists",
            "selector": "description"
          }
        ]
      },
      "failureMessage": "Interface {nodeId} is missing a description"
    }
  ]
}
```

### Your First TypeScript Rule

Create a file `my-rules.ts`:

```typescript
import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import { hasChildCommand, isShutdown, isPhysicalPort } from '@sentriflow/core/helpers/cisco';

export const InterfaceDescription: IRule = {
  id: 'MY-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  metadata: {
    level: 'warning',
    obu: 'Network Team',
    owner: 'NetOps',
    description: 'Interfaces should have descriptions',
  },
  check: (node: ConfigNode): RuleResult => {
    // Skip non-physical or shutdown interfaces
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return {
        passed: true,
        message: 'Not applicable',
        ruleId: 'MY-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check for description
    if (!hasChildCommand(node, 'description')) {
      return {
        passed: false,
        message: `Interface ${node.id} is missing a description`,
        ruleId: 'MY-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Interface has description',
      ruleId: 'MY-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};
```

### Running Your Rules

```bash
# With JSON rules
sentriflow scan --rules my-rules.json router.conf

# With TypeScript (after compilation)
sentriflow scan --rules ./dist/my-rules.js router.conf
```

---

## Understanding the AST

SentriFlow parses configuration text into an Abstract Syntax Tree (AST). Understanding this structure is key to writing effective rules.

### The ConfigNode Interface

```typescript
interface ConfigNode {
  id: string;           // Node identifier (e.g., "interface GigabitEthernet1")
  type: NodeType;       // 'section' | 'command' | 'comment'
  rawText: string;      // Original text from config
  params: string[];     // Parsed parameters
  children: ConfigNode[];  // Child nodes
  loc: {
    startLine: number;
    endLine: number;
  };
  indent: number;       // Indentation level
  blockDepth?: number;  // Nesting depth for sections
}
```

### Node Types

| Type | Description | Example |
|------|-------------|---------|
| `section` | Configuration block with children | `interface GigabitEthernet0/1` |
| `command` | Single configuration line | `ip address 10.0.0.1 255.255.255.0` |
| `comment` | Comment line (skipped) | `! This is a comment` |

### Example: Parsed Configuration

**Input:**
```
interface GigabitEthernet0/1
 description Uplink to Core
 ip address 10.0.0.1 255.255.255.0
 switchport mode trunk
```

**Resulting AST:**
```
ConfigNode {
  id: "interface GigabitEthernet0/1"
  type: "section"
  params: ["interface", "GigabitEthernet0/1"]
  children: [
    { id: "description Uplink to Core", type: "command", params: ["description", "Uplink to Core"] },
    { id: "ip address 10.0.0.1 255.255.255.0", type: "command", params: ["ip", "address", "10.0.0.1", "255.255.255.0"] },
    { id: "switchport mode trunk", type: "command", params: ["switchport", "mode", "trunk"] }
  ]
}
```

### Navigating the Tree

**Find a child by prefix:**
```typescript
const desc = node.children.find(c =>
  c.id.toLowerCase().startsWith('description')
);
```

**Check if child exists:**
```typescript
const hasDescription = node.children.some(c =>
  c.id.toLowerCase().startsWith('description')
);
```

**Get all matching children:**
```typescript
const ipAddresses = node.children.filter(c =>
  c.id.toLowerCase().startsWith('ip address')
);
```

---

## JSON Rules Guide

### File Structure

```json
{
  "$schema": "https://sentriflow.com.au/schemas/json-rules/v1.0.json",
  "version": "1.0",
  "meta": {
    "name": "Rule Pack Name",
    "description": "Description of rules",
    "author": "Author/Organization",
    "license": "Apache-2.0"
  },
  "rules": [
    { /* rule definitions */ }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Must be `"1.0"` |
| `meta` | No | Metadata about the rule pack |
| `rules` | Yes | Array of rule definitions |

### Rule Definition

```json
{
  "id": "SEC-001",
  "selector": "interface",
  "vendor": "cisco-ios",
  "category": "NIST-AC",
  "metadata": {
    "level": "error",
    "obu": "Security Team",
    "owner": "SecOps",
    "description": "What this rule checks",
    "remediation": "How to fix violations",
    "security": {
      "cwe": ["CWE-319"],
      "cvssScore": 7.5
    },
    "tags": [
      { "type": "security", "label": "encryption" },
      { "type": "security", "label": "network-security", "score": 7.5 }
    ]
  },
  "check": { /* check definition */ },
  "failureMessage": "Custom message with {nodeId} and {ruleId}"
}
```

### Tag Types

Rules can have typed tags for multi-dimensional categorization:

| Type | Use For | Examples |
|------|---------|----------|
| `security` | Security vulnerabilities, hardening | vlan-hopping, weak-crypto, access-control |
| `operational` | Operations & monitoring | logging, metrics, alerting |
| `compliance` | Compliance frameworks | nist-ac-3, pci-dss-1.2, cis-benchmark |
| `general` | General categorization | best-practice, deprecated, critical |

Tag objects support:
- `type` (required): One of `security`, `operational`, `compliance`, `general`
- `label` (required): Short identifier for the tag
- `text` (optional): Extended description
- `score` (optional): Severity/priority score (0-10)

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (pattern: `^[A-Z][A-Z0-9_-]{2,49}$`) |
| `selector` | No | Node prefix to match (e.g., "interface", "router bgp") |
| `vendor` | No | Vendor identifier or "common" for all vendors |
| `category` | No | Category for tree view grouping (string or array of strings) |
| `metadata` | Yes | Rule metadata (level, obu, owner required) |
| `check` | Yes | The validation logic |
| `failureMessage` | No | Custom message for failures (supports `{nodeId}`, `{ruleId}` placeholders) |
| `successMessage` | No | Custom message for passes (supports `{nodeId}`, `{ruleId}` placeholders) |

### Category Field

The `category` field groups rules in the VS Code tree view. Useful for compliance frameworks:

```json
{
  "id": "CMP-NIST-001",
  "category": "NIST-AC",
  ...
}
```

Multiple categories are supported:

```json
{
  "id": "CMP-MULTI-001",
  "category": ["NIST-AC-3", "PCI-DSS-8.1", "CIS-4.2"],
  ...
}
```

When omitted, rules are grouped under "Uncategorized" if category grouping is enabled in VS Code settings.

### Supported Vendors

`cisco-ios`, `cisco-nxos`, `juniper-junos`, `aruba-aoscx`, `aruba-aosswitch`, `aruba-wlc`, `paloalto-panos`, `arista-eos`, `vyos`, `fortinet-fortigate`, `extreme-exos`, `extreme-voss`, `huawei-vrp`, `mikrotik-routeros`, `nokia-sros`, `cumulus-linux`, `common`

### Check Types Reference

#### Understanding Check Semantics

**CRITICAL:** Check conditions define **failure** conditions, not success conditions.

- Check returns `true` = failure detected = rule **FAILS**
- Check returns `false` = no failure = rule **PASSES**

#### String Pattern Matching

**`match`** - Regex pattern matches node.id
```json
{
  "type": "match",
  "pattern": "^interface Gigabit",
  "flags": "i"
}
```

**`not_match`** - Regex pattern does NOT match
```json
{
  "type": "not_match",
  "pattern": "^loopback",
  "flags": "i"
}
```

#### Text Containment

**`contains`** - Case-insensitive substring search
```json
{
  "type": "contains",
  "text": "description"
}
```

**`not_contains`** - Substring NOT found
```json
{
  "type": "not_contains",
  "text": "shutdown"
}
```

#### Child Node Operations

**`child_exists`** - Child with prefix exists
```json
{
  "type": "child_exists",
  "selector": "description"
}
```

**`child_not_exists`** - No child with prefix
```json
{
  "type": "child_not_exists",
  "selector": "description"
}
```

**`child_matches`** - Child's id matches pattern
```json
{
  "type": "child_matches",
  "selector": "ip",
  "pattern": "^ip address [0-9.]+$"
}
```

**`child_contains`** - Child's id contains text
```json
{
  "type": "child_contains",
  "selector": "switchport",
  "text": "vlan"
}
```

#### Helper Functions

**`helper`** - Call a helper function
```json
{
  "type": "helper",
  "helper": "cisco.isTrunkPort",
  "args": [{ "$ref": "node" }],
  "negate": false
}
```

**Argument References:**

| Reference | Description |
|-----------|-------------|
| `{ "$ref": "node" }` | Full ConfigNode object |
| `{ "$ref": "node.id" }` | Node identifier string |
| `{ "$ref": "node.type" }` | Node type (`section`, `command`, `comment`) |
| `{ "$ref": "node.children" }` | Array of child nodes |
| `{ "$ref": "node.params" }` | Array of parameters |
| `{ "$ref": "node.rawText" }` | Original raw text from config |
| `"literal"` | Literal string value |
| `123` | Literal number |
| `true` / `false` | Literal boolean |
| `null` | Null value |

#### Expressions

**`expr`** - Sandboxed JavaScript expression
```json
{
  "type": "expr",
  "expr": "node.id.includes('Gigabit') && node.params.length > 0"
}
```

Available in expressions:
- `node` - The current ConfigNode (read-only)
- `Math`, `JSON`, `String`, `Number`, `Array`, `Object`, `RegExp`
- All helper functions

#### Logical Combinators

**`and`** - ALL conditions must be true
```json
{
  "type": "and",
  "conditions": [
    { "type": "child_exists", "selector": "shutdown" },
    { "type": "child_not_exists", "selector": "description" }
  ]
}
```

**`or`** - ANY condition must be true
```json
{
  "type": "or",
  "conditions": [
    { "type": "contains", "text": "loopback" },
    { "type": "contains", "text": "vlan" }
  ]
}
```

**`not`** - Negate a condition
```json
{
  "type": "not",
  "condition": { "type": "contains", "text": "shutdown" }
}
```

### Using Helper Functions

#### Common Helpers (No Namespace)

```json
{
  "type": "helper",
  "helper": "hasChildCommand",
  "args": [{ "$ref": "node" }, "switchport trunk allowed vlan"]
}
```

Common helpers: `hasChildCommand`, `getChildCommand`, `isShutdown`, `parseIp`, `isValidIpAddress`, `parseVlanId`, `isValidVlanId`, etc.

#### Vendor-Specific Helpers

```json
{
  "type": "helper",
  "helper": "cisco.isTrunkPort",
  "args": [{ "$ref": "node" }]
}
```

Namespaces: `cisco.`, `juniper.`, `arista.`, `aruba.`, `fortinet.`, `paloalto.`, `nokia.`, `huawei.`, `vyos.`, `mikrotik.`, `extreme.`, `cumulus.`

### Expression Security Constraints

| Constraint | Limit |
|------------|-------|
| Max expression length | 1,000 characters |
| Max regex pattern length | 500 characters |
| Execution timeout | 50 milliseconds |

**Blocked patterns:** Dynamic code execution functions, `require`, `import`, `Function`, `process`, `global`, `__proto__`, `constructor`, `prototype`, `setTimeout`, `fetch`, and similar dangerous constructs.

### Complete JSON Examples

#### Example 1: Cisco Trunk Port Validation

```json
{
  "id": "CISCO-TRUNK-001",
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
      {
        "type": "helper",
        "helper": "cisco.isTrunkPort",
        "args": [{ "$ref": "node" }]
      },
      {
        "type": "helper",
        "helper": "cisco.isPhysicalPort",
        "args": [{ "$ref": "node.id" }]
      },
      {
        "type": "helper",
        "helper": "isShutdown",
        "args": [{ "$ref": "node" }],
        "negate": true
      },
      {
        "type": "child_not_exists",
        "selector": "switchport trunk allowed vlan"
      }
    ]
  },
  "failureMessage": "Trunk port {nodeId} allows all VLANs - restrict with explicit list"
}
```

**Logic:** Rule FAILS if interface IS a trunk AND IS physical AND is NOT shutdown AND does NOT have allowed VLAN list.

#### Example 2: VTY Access Control

```json
{
  "id": "SEC-VTY-001",
  "selector": "line vty",
  "vendor": "cisco-ios",
  "metadata": {
    "level": "error",
    "obu": "Security",
    "owner": "SecOps",
    "description": "VTY lines must have access-class configured",
    "remediation": "Add 'access-class <acl> in'",
    "security": {
      "cwe": ["CWE-284"]
    },
    "tags": [
      { "type": "security", "label": "access-control" },
      { "type": "security", "label": "remote-access" }
    ]
  },
  "check": {
    "type": "child_not_exists",
    "selector": "access-class"
  },
  "failureMessage": "VTY line {nodeId} is missing access-class"
}
```

#### Example 3: Multi-Vendor Interface Check

```json
{
  "id": "NET-DOC-001",
  "selector": "interface",
  "vendor": "common",
  "metadata": {
    "level": "info",
    "obu": "Documentation",
    "owner": "NetOps",
    "description": "All interfaces should be documented"
  },
  "check": {
    "type": "and",
    "conditions": [
      {
        "type": "expr",
        "expr": "node.type === 'section' && node.id.toLowerCase().startsWith('interface')"
      },
      {
        "type": "child_not_exists",
        "selector": "description"
      }
    ]
  }
}
```

---

## TypeScript Rules Guide

### The IRule Interface

```typescript
interface IRule {
  id: string;                              // Unique rule ID
  selector?: string;                       // Node prefix to match
  vendor?: RuleVendor | RuleVendor[];      // Target vendor(s)
  category?: string | string[];            // Category for tree view grouping
  check: (node: ConfigNode, context: Context) => RuleResult;
  metadata: RuleMetadata;
}
```

The `category` field works the same as in JSON rules - use it to group rules by compliance framework or custom categories in the VS Code tree view.

### RuleResult Return Type

```typescript
interface RuleResult {
  passed: boolean;          // true = passed, false = failed
  message: string;          // Explanation of result
  ruleId: string;           // Your rule ID
  nodeId: string;           // Node being checked (node.id)
  level: 'error' | 'warning' | 'info';
  remediation?: string;     // Optional fix steps
  loc?: {                   // Source location
    startLine: number;
    endLine: number;
  };
}
```

### Context Object

```typescript
interface Context {
  getAst?: () => ConfigNode[];  // Lazy getter for full AST
}
```

**Note:** Only use `context.getAst()` when you need cross-reference validation. Most rules should only inspect the current node.

### Importing Helpers

```typescript
// Common helpers (from core)
import {
  hasChildCommand,
  getChildCommand,
  getChildCommands,
  isShutdown,
  parseIp,
  isValidIpAddress,
  parseVlanId,
  isValidVlanId,
} from '@sentriflow/core';

// Cisco helpers
import {
  isPhysicalPort,
  isTrunkPort,
  isAccessPort,
  isTrunkToNonCisco,
  hasOspfAuthentication,
  getBgpNeighbors,
} from '@sentriflow/core/helpers/cisco';

// Juniper helpers
import {
  findStanza,
  findStanzas,
  isSshV2Only,
  hasLoginBanner,
} from '@sentriflow/core/helpers/juniper';
```

### Security Metadata and Tags

For security-focused rules, include CWE, CVSS, and typed tags:

```typescript
metadata: {
  level: 'error',
  obu: 'Security',
  owner: 'SecOps',
  description: 'SSH must use version 2 only',
  remediation: 'Configure "ip ssh version 2"',
  security: {
    cwe: ['CWE-327'],           // Weak cryptography
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  },
  tags: [
    { type: 'security', label: 'ssh', score: 7.5 },
    { type: 'security', label: 'encryption' },
    { type: 'security', label: 'protocol-version' },
  ],
},
```

Tag types: `security`, `operational`, `compliance`, `general`

### Complete TypeScript Examples

#### Example 1: Cisco Trunk Native VLAN

```typescript
import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import { isDefaultVlan } from '@sentriflow/core';
import {
  isPhysicalPort,
  isTrunkPort,
  isShutdown,
  getChildCommand,
} from '@sentriflow/core/helpers/cisco';

export const TrunkNativeVlanNotOne: IRule = {
  id: 'NET-TRUNK-002',
  selector: 'interface',
  vendor: 'cisco-ios',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    description: 'Native VLAN must not be VLAN 1',
    remediation: 'Configure "switchport trunk native vlan <non-1-vlan>"',
  },
  check: (node: ConfigNode): RuleResult => {
    // Skip non-applicable interfaces
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return {
        passed: true,
        message: 'Not applicable',
        ruleId: 'NET-TRUNK-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Only check trunk ports
    if (!isTrunkPort(node)) {
      return {
        passed: true,
        message: 'Not a trunk port',
        ruleId: 'NET-TRUNK-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check for native VLAN configuration
    const nativeVlanCmd = getChildCommand(node, 'switchport trunk native vlan');

    if (!nativeVlanCmd) {
      return {
        passed: false,
        message: `Trunk port uses default native VLAN 1`,
        ruleId: 'NET-TRUNK-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    // Check if explicitly set to VLAN 1
    const vlanNum = nativeVlanCmd.params[4];
    if (vlanNum && isDefaultVlan(vlanNum)) {
      return {
        passed: false,
        message: `Trunk port explicitly uses native VLAN 1`,
        ruleId: 'NET-TRUNK-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Native VLAN is not VLAN 1',
      ruleId: 'NET-TRUNK-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};
```

#### Example 2: Juniper Root Authentication

```typescript
import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import { hasChildCommand } from '@sentriflow/core';
import { findStanza } from '@sentriflow/core/helpers/juniper';

export const RootAuthRequired: IRule = {
  id: 'JUN-SYS-001',
  selector: 'system',
  vendor: 'juniper-junos',
  category: ['NIST-IA-5', 'CIS-5.1'],  // Compliance framework categories
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    description: 'System must have root-authentication configured',
    remediation: 'Configure root-authentication with encrypted-password or ssh-rsa',
    security: {
      cwe: ['CWE-306'],
    },
    tags: [
      { type: 'security', label: 'authentication' },
      { type: 'security', label: 'root-access' },
    ],
  },
  check: (node: ConfigNode): RuleResult => {
    // Find root-authentication stanza
    const rootAuth = findStanza(node, 'root-authentication');

    if (!rootAuth) {
      return {
        passed: false,
        message: 'System missing root-authentication configuration',
        ruleId: 'JUN-SYS-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    // Check for password or SSH key
    const hasPassword = hasChildCommand(rootAuth, 'encrypted-password');
    const hasSshKey = hasChildCommand(rootAuth, 'ssh-rsa') ||
                      hasChildCommand(rootAuth, 'ssh-ecdsa');

    if (!hasPassword && !hasSshKey) {
      return {
        passed: false,
        message: 'Root authentication has no password or SSH key',
        ruleId: 'JUN-SYS-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Root authentication is properly configured',
      ruleId: 'JUN-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};
```

#### Example 3: Multi-Vendor IP Validation

```typescript
import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import { parseIp, isMulticastAddress, isBroadcastAddress } from '@sentriflow/core';

export const NoMulticastBroadcastIp: IRule = {
  id: 'NET-IP-001',
  selector: 'ip address',
  vendor: 'common',  // Applies to all vendors
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    description: 'IP addresses must be valid unicast addresses',
    remediation: 'Configure a valid unicast IP address',
  },
  check: (node: ConfigNode): RuleResult => {
    const ipStr = node.params[2];

    // Skip dynamic assignments
    if (!ipStr || ['dhcp', 'negotiated', 'pool'].includes(ipStr.toLowerCase())) {
      return {
        passed: true,
        message: 'Dynamic IP assignment',
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Parse and validate IP
    const ipNum = parseIp(ipStr);

    if (ipNum === null) {
      return {
        passed: false,
        message: `Invalid IP format: ${ipStr}`,
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (isMulticastAddress(ipNum)) {
      return {
        passed: false,
        message: `${ipStr} is a multicast address`,
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (isBroadcastAddress(ipNum)) {
      return {
        passed: false,
        message: `${ipStr} is the broadcast address`,
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Valid unicast IP: ${ipStr}`,
      ruleId: 'NET-IP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};
```

---

## Helper Functions Reference

### Common Helpers

| Function | Signature | Description |
|----------|-----------|-------------|
| `hasChildCommand` | `(node, prefix) => boolean` | Check if child with prefix exists |
| `getChildCommand` | `(node, prefix) => ConfigNode?` | Get first matching child |
| `getChildCommands` | `(node, prefix) => ConfigNode[]` | Get all matching children |
| `isShutdown` | `(node) => boolean` | Check if interface is shutdown |
| `parseIp` | `(addr) => number \| null` | Parse IP to 32-bit integer |
| `isValidIpAddress` | `(value) => boolean` | Validate IP format |
| `isMulticastAddress` | `(ipNum) => boolean` | Check 224.x.x.x - 239.x.x.x |
| `isBroadcastAddress` | `(ipNum) => boolean` | Check 255.255.255.255 |
| `isPrivateAddress` | `(ipNum) => boolean` | Check RFC 1918 ranges |
| `parseCidr` | `(cidr) => { ip, prefix, mask }` | Parse CIDR notation |
| `isIpInCidr` | `(ip, cidr) => boolean` | Check if IP in range |
| `parseVlanId` | `(value) => number \| null` | Parse VLAN ID (1-4094) |
| `isValidVlanId` | `(id) => boolean` | Validate VLAN ID |
| `isDefaultVlan` | `(id) => boolean` | Check if VLAN 1 |
| `parsePort` | `(value) => number \| null` | Parse port number |
| `isValidPort` | `(num) => boolean` | Validate port 0-65535 |
| `isValidMacAddress` | `(addr) => boolean` | Validate MAC format |

### Cisco Helpers (`cisco.` namespace)

| Function | Description |
|----------|-------------|
| `isPhysicalPort(name)` | Not loopback, vlan, tunnel, port-channel |
| `isTrunkPort(node)` | Has "switchport mode trunk" |
| `isAccessPort(node)` | Has "switchport mode access" |
| `isTrunkToNonCisco(node)` | Trunk to non-Cisco device |
| `isExternalFacing(node)` | WAN/external-facing interface |
| `isEndpointPort(node)` | Connected to user device |
| `hasOspfAuthentication(node)` | OSPF auth configured |
| `hasBgpNeighborPassword(cmds)` | BGP neighbor has password |
| `hasVtyAccessClass(node)` | VTY has access-class |
| `getSshVersion(node)` | Returns SSH version (1 or 2) |
| `hasPasswordEncryption(node)` | Service password-encryption |

### Juniper Helpers (`juniper.` namespace)

| Function | Description |
|----------|-------------|
| `findStanza(node, name)` | Find child stanza by name |
| `findStanzas(node, pattern)` | Find stanzas matching regex |
| `isSshV2Only(node)` | SSH configured for v2 only |
| `hasTelnetService(node)` | Telnet service enabled |
| `hasLoginBanner(node)` | Login banner configured |
| `hasOspfAreaAuth(node)` | OSPF area has authentication |
| `hasRemoteSyslog(node)` | Remote syslog configured |
| `getInterfaceUnits(node)` | Get all unit children |

### Other Vendor Helpers

Additional helpers available for: `arista`, `aruba`, `fortinet`, `paloalto`, `nokia`, `huawei`, `vyos`, `mikrotik`, `extreme`, `cumulus`

See the [Helper Functions Reference](./helpers/README.md) for comprehensive documentation of all helper functions, including complete function signatures, parameters, return types, and usage examples.

---

## Best Practices

### Rule Naming Conventions

| Pattern | Use For | Examples |
|---------|---------|----------|
| `SEC-XXX` | Security rules | `SEC-001`, `SEC-SSH-001` |
| `NET-XXX` | Network/general rules | `NET-TRUNK-001`, `NET-IP-001` |
| `CMP-XXX` | Compliance rules | `CMP-PCI-001` |
| `<VENDOR>-XXX` | Vendor-specific | `CISCO-001`, `JUN-SYS-001` |

### Performance Tips

1. **Always use selectors** - Reduces nodes the rule must check
   ```typescript
   selector: 'interface'  // Only runs on interface nodes
   ```

2. **Return early** - Skip non-applicable nodes immediately
   ```typescript
   if (!isPhysicalPort(node.id) || isShutdown(node)) {
     return { passed: true, message: 'Not applicable', ... };
   }
   ```

3. **Avoid `context.getAst()`** - Only use when cross-referencing is required

4. **Use helpers** - They're optimized and handle edge cases

### Testing Your Rules

```typescript
import { SchemaAwareParser, RuleEngine } from '@sentriflow/core';
import { MyRule } from './my-rules';

const config = `
interface GigabitEthernet0/1
 switchport mode trunk
`;

const parser = new SchemaAwareParser();
const nodes = parser.parse(config);

const engine = new RuleEngine();
const results = engine.run(nodes, [MyRule]);
console.log(results);
```

### Documentation Requirements

1. **Always include `description`** - What the rule checks
2. **Always include `remediation`** - How to fix violations
3. **Add `security` metadata** for security rules - CWE, CVSS scores
4. **Add typed `tags`** - Use appropriate type (security, operational, compliance, general)
5. **Use meaningful `failureMessage`** - Include `{nodeId}` for context

---

## Troubleshooting

### Common Errors

#### "Invalid rule ID format"

Rule IDs must match pattern `^[A-Z][A-Z0-9_-]{2,49}$`

```json
// Bad
"id": "my-rule-1"

// Good
"id": "MY-RULE-001"
```

#### "Unknown helper function"

Check the helper namespace and spelling:

```json
// Bad - wrong namespace
"helper": "isTrunkPort"

// Good - Cisco namespace
"helper": "cisco.isTrunkPort"

// Good - common helper (no namespace)
"helper": "hasChildCommand"
```

#### "Expression security violation"

Remove blocked patterns from expressions. Dynamic code execution and access to global objects are not allowed:

```json
// Bad - uses blocked patterns
"expr": "require('fs').readFileSync(...)"

// Good - use allowed methods
"expr": "node.id.includes('Gigabit')"
```

#### "Check always fails/passes"

Remember: check defines **failure** condition, not success.

```json
// This FAILS when description DOES NOT exist
"check": { "type": "child_not_exists", "selector": "description" }
```

#### Rule not running

1. Check `selector` matches your target nodes
2. Verify `vendor` matches the config's vendor
3. Ensure the rule file is correctly loaded

### Expression Limits

If your expression is rejected:
- Max length: 1,000 characters
- Max regex pattern: 500 characters
- Timeout: 50ms

Break complex logic into multiple conditions using `and`/`or`.

---

## Next Steps

- Review example rules in `packages/rules-default/src/`
- Check JSON rule examples in `packages/rules-default/src/json/`
- See vendor-specific helpers in `packages/core/src/helpers/`
- Run `sentriflow scan --help` for CLI options

# Extreme Networks Helper Functions Reference

Extreme Networks helpers provide specialized functions for validating EXOS (ExtremeXOS) and VOSS (VSP Operating System Software) configurations. These helpers understand Extreme-specific syntax, command structures, and feature sets including SPBM fabric technology.

## Overview

Extreme Networks offers two primary operating systems:

- **EXOS (ExtremeXOS)**: Runs on Summit and ExtremeSwitching series switches. Uses a command-based configuration style with `create`, `configure`, and `enable` keywords.
- **VOSS (VSP Operating System Software)**: Runs on VSP (Virtual Services Platform) series switches. Uses a Cisco-like hierarchical configuration style with support for SPB-M (Shortest Path Bridging - MAC) fabric technology.

## Import Statement

```typescript
import {
  isExosVlanCreate,
  getExosVlanName,
  hasVossSpbm,
  getVossVlanIsid,
  // ... other helpers
} from '@sentriflow/core/helpers/extreme';
```

Or import everything:

```typescript
import * as extreme from '@sentriflow/core/helpers/extreme';
```

---

## EXOS Helpers

### 1. VLAN Configuration

Functions for working with EXOS VLAN configurations.

---

### isExosVlanCreate

Check if node is an EXOS VLAN creation command.

**Signature:**
```typescript
function isExosVlanCreate(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode to check |

**Returns:** `boolean` - `true` if it's a `create vlan` command.

**Example:**
```typescript
import { isExosVlanCreate } from '@sentriflow/core/helpers/extreme';

// Matches: create vlan "Management"
if (isExosVlanCreate(node)) {
  // Process VLAN creation
}
```

---

### getExosVlanName

Extract VLAN name from EXOS VLAN command.

**Signature:**
```typescript
function getExosVlanName(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode containing the VLAN command |

**Returns:** `string | undefined` - The VLAN name or `undefined` if not found.

**Example:**
```typescript
import { getExosVlanName } from '@sentriflow/core/helpers/extreme';

// For: create vlan "Management"
const vlanName = getExosVlanName(node);
// Returns: "Management"

// For: configure vlan "Data" tag 100
const vlanName2 = getExosVlanName(node2);
// Returns: "Data"
```

---

### getExosVlanTag

Extract VLAN tag from EXOS VLAN command.

**Signature:**
```typescript
function getExosVlanTag(node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode containing the VLAN command |

**Returns:** `number | undefined` - The VLAN tag number or `undefined` if not found.

**Example:**
```typescript
import { getExosVlanTag } from '@sentriflow/core/helpers/extreme';

// For: configure vlan "Data" tag 100
const tag = getExosVlanTag(node);
// Returns: 100
```

---

### 2. General Configuration

Functions for identifying EXOS configuration commands.

---

### isExosConfigureCommand

Check if EXOS command is a configure command.

**Signature:**
```typescript
function isExosConfigureCommand(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode to check |

**Returns:** `boolean` - `true` if it's a `configure` command.

**Example:**
```typescript
import { isExosConfigureCommand } from '@sentriflow/core/helpers/extreme';

// Matches: configure vlan "Data" add ports 1:1-1:24 tagged
if (isExosConfigureCommand(node)) {
  // Process configure command
}
```

---

### 3. Management Plane

Functions for validating EXOS management configurations.

---

### hasExosSysname

Check if EXOS has SNMP sysname configured.

**Signature:**
```typescript
function hasExosSysname(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SNMP sysname is configured.

**Example:**
```typescript
import { hasExosSysname } from '@sentriflow/core/helpers/extreme';

if (!hasExosSysname(ast)) {
  return { passed: false, message: 'Configure SNMP sysname for device identification' };
}
```

---

### getExosSysname

Get EXOS sysname value.

**Signature:**
```typescript
function getExosSysname(ast: ConfigNode[]): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `string | undefined` - The sysname or `undefined` if not configured.

**Example:**
```typescript
import { getExosSysname } from '@sentriflow/core/helpers/extreme';

// For: configure snmp sysname "core-switch-01"
const sysname = getExosSysname(ast);
// Returns: "core-switch-01"
```

---

### hasExosSntp

Check if EXOS has SNTP configured.

**Signature:**
```typescript
function hasExosSntp(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SNTP is configured.

**Example:**
```typescript
import { hasExosSntp } from '@sentriflow/core/helpers/extreme';

if (!hasExosSntp(ast)) {
  return { passed: false, message: 'Configure SNTP for time synchronization' };
}
```

---

### isExosSntpEnabled

Check if EXOS SNTP is enabled.

**Signature:**
```typescript
function isExosSntpEnabled(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SNTP is enabled.

**Example:**
```typescript
import { hasExosSntp, isExosSntpEnabled } from '@sentriflow/core/helpers/extreme';

if (hasExosSntp(ast) && !isExosSntpEnabled(ast)) {
  return { passed: false, message: 'SNTP is configured but not enabled' };
}
```

---

### hasExosSyslog

Check if EXOS has syslog configured.

**Signature:**
```typescript
function hasExosSyslog(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if syslog is configured.

**Checks for:** `configure syslog` or `configure log target` commands.

**Example:**
```typescript
import { hasExosSyslog } from '@sentriflow/core/helpers/extreme';

if (!hasExosSyslog(ast)) {
  return { passed: false, message: 'Configure syslog for centralized logging' };
}
```

---

### 4. Security

Functions for validating EXOS security configurations.

---

### hasExosSsh2

Check if EXOS has SSH2 enabled.

**Signature:**
```typescript
function hasExosSsh2(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SSH2 is configured.

**Checks for:** `enable ssh2` or `configure ssh2` commands.

**Example:**
```typescript
import { hasExosSsh2 } from '@sentriflow/core/helpers/extreme';

if (!hasExosSsh2(ast)) {
  return { passed: false, message: 'Enable SSH2 for secure management access' };
}
```

---

### hasExosRadius

Check if EXOS has RADIUS configured.

**Signature:**
```typescript
function hasExosRadius(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if RADIUS is configured.

**Example:**
```typescript
import { hasExosRadius, hasExosTacacs } from '@sentriflow/core/helpers/extreme';

if (!hasExosRadius(ast) && !hasExosTacacs(ast)) {
  return { passed: false, message: 'Configure RADIUS or TACACS for centralized authentication' };
}
```

---

### hasExosTacacs

Check if EXOS has TACACS configured.

**Signature:**
```typescript
function hasExosTacacs(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if TACACS is configured.

**Example:**
```typescript
import { hasExosTacacs } from '@sentriflow/core/helpers/extreme';

if (hasExosTacacs(ast)) {
  // TACACS+ is configured for AAA
}
```

---

### 5. Link Aggregation

Functions for working with EXOS link aggregation (sharing).

---

### isExosLag

Check if EXOS LAG (sharing) is configured.

**Signature:**
```typescript
function isExosLag(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode to check |

**Returns:** `boolean` - `true` if it's an `enable sharing` command.

**Example:**
```typescript
import { isExosLag } from '@sentriflow/core/helpers/extreme';

// Matches: enable sharing 1:1 grouping 1:1-1:2 algorithm address-based L3_L4
if (isExosLag(node)) {
  // Process LAG configuration
}
```

---

### getExosLagMasterPort

Extract LAG master port from EXOS sharing command.

**Signature:**
```typescript
function getExosLagMasterPort(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode containing the sharing command |

**Returns:** `string | undefined` - The master port (e.g., "1:1") or `undefined`.

**Example:**
```typescript
import { getExosLagMasterPort, isExosLag } from '@sentriflow/core/helpers/extreme';

if (isExosLag(node)) {
  const masterPort = getExosLagMasterPort(node);
  // For: enable sharing 1:1 grouping 1:1-1:2
  // Returns: "1:1"
}
```

---

### 6. High Availability

Functions for validating EXOS high availability configurations.

---

### hasExosEaps

Check if EXOS EAPS is configured.

**Signature:**
```typescript
function hasExosEaps(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if EAPS (Ethernet Automatic Protection Switching) is configured.

**Checks for:** `create eaps` or `configure eaps` commands.

**Example:**
```typescript
import { hasExosEaps } from '@sentriflow/core/helpers/extreme';

if (hasExosEaps(ast)) {
  // EAPS ring protection is configured
}
```

---

### hasExosStacking

Check if EXOS stacking is enabled.

**Signature:**
```typescript
function hasExosStacking(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if stacking is enabled.

**Checks for:** `enable stacking` or `configure stacking` commands.

**Example:**
```typescript
import { hasExosStacking } from '@sentriflow/core/helpers/extreme';

if (hasExosStacking(ast)) {
  // Switch is part of a stack
}
```

---

### hasExosMlag

Check if EXOS MLAG is configured.

**Signature:**
```typescript
function hasExosMlag(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if MLAG (Multi-switch Link Aggregation Group) is configured.

**Checks for:** `create mlag peer` or `configure mlag peer` commands.

**Example:**
```typescript
import { hasExosMlag } from '@sentriflow/core/helpers/extreme';

if (hasExosMlag(ast)) {
  // MLAG is configured for multi-chassis LAG
}
```

---

## VOSS Helpers

### 1. VLAN Configuration

Functions for working with VOSS VLAN configurations.

---

### isVossVlanCreate

Check if node is a VOSS VLAN creation command.

**Signature:**
```typescript
function isVossVlanCreate(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode to check |

**Returns:** `boolean` - `true` if it's a `vlan create` command.

**Example:**
```typescript
import { isVossVlanCreate } from '@sentriflow/core/helpers/extreme';

// Matches: vlan create 100 name "Data" type port-mstprstp 0
if (isVossVlanCreate(node)) {
  // Process VLAN creation
}
```

---

### getVossVlanId

Extract VLAN ID from VOSS VLAN command.

**Signature:**
```typescript
function getVossVlanId(node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode containing the VLAN command |

**Returns:** `number | undefined` - The VLAN ID or `undefined` if not found.

**Example:**
```typescript
import { getVossVlanId } from '@sentriflow/core/helpers/extreme';

// For: vlan create 100 name "Data" type port-mstprstp 0
const vlanId = getVossVlanId(node);
// Returns: 100

// Also works with: vlan members 100 add 1/1-1/24
// And: vlan i-sid 100 10100
```

---

### 2. SPB-M Fabric

Functions for working with VOSS SPB-M (Shortest Path Bridging - MAC) fabric configurations.

---

### hasVossSpbm

Check if VOSS has SPBM configured.

**Signature:**
```typescript
function hasVossSpbm(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SPBM is configured.

**Checks for:** `spbm` commands or `router isis` with SPBM configuration.

**Example:**
```typescript
import { hasVossSpbm } from '@sentriflow/core/helpers/extreme';

if (hasVossSpbm(ast)) {
  // Switch is part of SPB-M fabric
}
```

---

### hasVossIsis

Check if VOSS has ISIS configured.

**Signature:**
```typescript
function hasVossIsis(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if ISIS is configured.

**Example:**
```typescript
import { hasVossIsis, hasVossSpbm } from '@sentriflow/core/helpers/extreme';

// ISIS is required for SPB-M fabric
if (hasVossSpbm(ast) && !hasVossIsis(ast)) {
  return { passed: false, message: 'ISIS required for SPB-M fabric' };
}
```

---

### hasVossVlanIsid

Check if VOSS has I-SID configured for VLAN.

**Signature:**
```typescript
function hasVossVlanIsid(ast: ConfigNode[], vlanId: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |
| vlanId | `number` | The VLAN ID to check |

**Returns:** `boolean` - `true` if I-SID is configured for the VLAN.

**Example:**
```typescript
import { hasVossVlanIsid, getVossVlanId } from '@sentriflow/core/helpers/extreme';

const vlanId = getVossVlanId(node);
if (vlanId && !hasVossVlanIsid(ast, vlanId)) {
  return { passed: false, message: `VLAN ${vlanId} has no I-SID mapping` };
}
```

---

### getVossVlanIsid

Get I-SID for a VOSS VLAN.

**Signature:**
```typescript
function getVossVlanIsid(ast: ConfigNode[], vlanId: number): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |
| vlanId | `number` | The VLAN ID |

**Returns:** `number | undefined` - The I-SID or `undefined` if not configured.

**Example:**
```typescript
import { getVossVlanIsid } from '@sentriflow/core/helpers/extreme';

// For: vlan i-sid 100 10100
const isid = getVossVlanIsid(ast, 100);
// Returns: 10100
```

---

### hasVossDvr

Check if VOSS has DVR (Distributed Virtual Routing) configured.

**Signature:**
```typescript
function hasVossDvr(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if DVR is configured.

**Checks for:** `dvr leaf` or `dvr controller` commands.

**Example:**
```typescript
import { hasVossDvr } from '@sentriflow/core/helpers/extreme';

if (hasVossDvr(ast)) {
  // Distributed Virtual Routing is enabled
}
```

---

### 3. Interface Configuration

Functions for working with VOSS interface configurations.

---

### isVossGigabitEthernet

Check if VOSS interface is a GigabitEthernet.

**Signature:**
```typescript
function isVossGigabitEthernet(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode to check |

**Returns:** `boolean` - `true` if it's a GigabitEthernet interface.

**Example:**
```typescript
import { isVossGigabitEthernet } from '@sentriflow/core/helpers/extreme';

// Matches: interface GigabitEthernet 1/1
if (isVossGigabitEthernet(node)) {
  // Process physical interface
}
```

---

### isVossMlt

Check if VOSS interface is an MLT (Multi-Link Trunk).

**Signature:**
```typescript
function isVossMlt(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode to check |

**Returns:** `boolean` - `true` if it's an MLT interface.

**Checks for:** `interface mlt` or `mlt` commands.

**Example:**
```typescript
import { isVossMlt } from '@sentriflow/core/helpers/extreme';

// Matches: interface mlt 1
// Also matches: mlt 1 enable
if (isVossMlt(node)) {
  // Process MLT configuration
}
```

---

### getVossMltId

Get VOSS MLT ID.

**Signature:**
```typescript
function getVossMltId(node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode containing the MLT command |

**Returns:** `number | undefined` - The MLT ID or `undefined`.

**Example:**
```typescript
import { getVossMltId, isVossMlt } from '@sentriflow/core/helpers/extreme';

if (isVossMlt(node)) {
  const mltId = getVossMltId(node);
  // For: interface mlt 1
  // Returns: 1
}
```

---

### isVossShutdown

Check if VOSS interface is shutdown.

**Signature:**
```typescript
function isVossShutdown(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode to check |

**Returns:** `boolean` - `true` if interface is shutdown.

**Note:** Returns `true` only if `shutdown` is present and `no shutdown` is not present.

**Example:**
```typescript
import { isVossShutdown } from '@sentriflow/core/helpers/extreme';

if (isVossShutdown(interfaceNode)) {
  return { passed: true, message: 'Interface is shutdown - skipping' };
}
```

---

### getVossDefaultVlan

Get VOSS interface default VLAN.

**Signature:**
```typescript
function getVossDefaultVlan(node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `number | undefined` - The default VLAN ID or `undefined`.

**Example:**
```typescript
import { getVossDefaultVlan } from '@sentriflow/core/helpers/extreme';

const defaultVlan = getVossDefaultVlan(interfaceNode);
if (defaultVlan === 1) {
  return { passed: false, message: 'Avoid using default VLAN 1' };
}
```

---

### 4. Management Plane

Functions for validating VOSS management configurations.

---

### hasVossSnmpName

Check if VOSS has snmp-server name configured.

**Signature:**
```typescript
function hasVossSnmpName(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if snmp-server name is configured.

**Example:**
```typescript
import { hasVossSnmpName } from '@sentriflow/core/helpers/extreme';

if (!hasVossSnmpName(ast)) {
  return { passed: false, message: 'Configure snmp-server name for device identification' };
}
```

---

### getVossSnmpName

Get VOSS snmp-server name.

**Signature:**
```typescript
function getVossSnmpName(ast: ConfigNode[]): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `string | undefined` - The name or `undefined` if not configured.

**Example:**
```typescript
import { getVossSnmpName } from '@sentriflow/core/helpers/extreme';

// For: snmp-server name "vsp-core-01"
const name = getVossSnmpName(ast);
// Returns: "vsp-core-01"
```

---

### hasVossNtp

Check if VOSS has NTP configured.

**Signature:**
```typescript
function hasVossNtp(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if NTP is configured.

**Checks for:** `ntp server` commands.

**Example:**
```typescript
import { hasVossNtp } from '@sentriflow/core/helpers/extreme';

if (!hasVossNtp(ast)) {
  return { passed: false, message: 'Configure NTP for time synchronization' };
}
```

---

### hasVossLogging

Check if VOSS has logging configured.

**Signature:**
```typescript
function hasVossLogging(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if logging is configured.

**Checks for:** `logging host` or `logging server` commands.

**Example:**
```typescript
import { hasVossLogging } from '@sentriflow/core/helpers/extreme';

if (!hasVossLogging(ast)) {
  return { passed: false, message: 'Configure logging for centralized log collection' };
}
```

---

### hasVossSsh

Check if VOSS has SSH enabled.

**Signature:**
```typescript
function hasVossSsh(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SSH is configured.

**Example:**
```typescript
import { hasVossSsh } from '@sentriflow/core/helpers/extreme';

if (!hasVossSsh(ast)) {
  return { passed: false, message: 'Enable SSH for secure management access' };
}
```

---

### 5. Link Aggregation

Functions for working with VOSS link aggregation.

---

### hasVossLacp

Check if VOSS has LACP configured on interface.

**Signature:**
```typescript
function hasVossLacp(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if LACP is configured.

**Checks for:** `lacp enable` or `lacp key` in interface children.

**Example:**
```typescript
import { hasVossLacp, isVossGigabitEthernet } from '@sentriflow/core/helpers/extreme';

if (isVossGigabitEthernet(node) && hasVossLacp(node)) {
  // Interface is part of an LACP bundle
}
```

---

### 6. High Availability

Functions for validating VOSS high availability configurations.

---

### hasVossCfm

Check if VOSS has CFM (Connectivity Fault Management) configured.

**Signature:**
```typescript
function hasVossCfm(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if CFM is configured.

**Example:**
```typescript
import { hasVossCfm } from '@sentriflow/core/helpers/extreme';

if (hasVossCfm(ast)) {
  // CFM is configured for Ethernet OAM
}
```

---

## See Also

- [Helper Functions Overview](./README.md)
- [Common Helpers](./common.md) - Platform-agnostic helper functions
- [Cisco Helpers](./cisco.md) - Similar hierarchical configuration style (VOSS)
- [Arista Helpers](./arista.md) - Similar command syntax
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - How to use helpers in rules

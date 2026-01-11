# SentriFlow Helper Functions Reference

This directory contains comprehensive documentation for all helper functions available for writing SentriFlow validation rules.

## Overview

Helper functions simplify rule authoring by providing reusable, tested logic for common network configuration checks. They handle vendor-specific syntax variations and edge cases, allowing you to focus on the validation logic.

## Quick Links

| Document | Description |
|----------|-------------|
| [Common Helpers](./common.md) | Shared utilities for IP, VLAN, MAC, and node navigation |
| [Cisco Helpers](./cisco.md) | Cisco IOS/IOS-XE routers and switches |
| [Juniper Helpers](./juniper.md) | Juniper JunOS devices |
| [Arista Helpers](./arista.md) | Arista EOS switches |
| [Aruba Helpers](./aruba.md) | Aruba AOS-CX, AOS-Switch, and WLC |
| [Fortinet Helpers](./fortinet.md) | Fortinet FortiGate firewalls |
| [Huawei Helpers](./huawei.md) | Huawei VRP routers/switches |
| [Extreme Helpers](./extreme.md) | Extreme Networks EXOS and VOSS |
| [Cumulus Helpers](./cumulus.md) | NVIDIA Cumulus Linux |
| [Palo Alto Helpers](./paloalto.md) | Palo Alto PAN-OS firewalls |
| [Nokia Helpers](./nokia.md) | Nokia SR OS |
| [VyOS Helpers](./vyos.md) | VyOS/EdgeOS routers |
| [MikroTik Helpers](./mikrotik.md) | MikroTik RouterOS |

## Import Patterns

### Common Helpers

```typescript
import {
  hasChildCommand,
  getChildCommand,
  parseIp,
  isValidVlanId,
} from '@sentriflow/core/helpers/common';
```

### Vendor-Specific Helpers

```typescript
// Cisco
import { isPhysicalPort, isTrunkPort } from '@sentriflow/core/helpers/cisco';

// Juniper
import { findStanza, isSshV2Only } from '@sentriflow/core/helpers/juniper';

// Arista
import { hasDhcpSnooping, getBgpNeighborsWithoutAuth } from '@sentriflow/core/helpers/arista';
```

### All Helpers (Namespaced)

```typescript
import * as helpers from '@sentriflow/core/helpers';

// Access via namespaces
helpers.cisco.isPhysicalPort('GigabitEthernet0/1');
helpers.juniper.findStanza(node, 'system');
helpers.common.parseIp('10.0.0.1');
```

## Using Helpers in JSON Rules

In JSON rules, call helpers using the `helper` check type:

```json
{
  "type": "helper",
  "helper": "cisco.isTrunkPort",
  "args": [{ "$ref": "node" }]
}
```

Common helpers (no namespace):

```json
{
  "type": "helper",
  "helper": "hasChildCommand",
  "args": [{ "$ref": "node" }, "description"]
}
```

See the [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) for complete JSON rule syntax.

## Function Categories

Each vendor's helpers are organized into these functional categories:

### 1. Interface Identification
Functions that classify interface types: physical ports, loopbacks, VLANs, tunnels, LAGs, etc.
- `isPhysicalPort()`, `isLoopback()`, `isTrunkPort()`, `isAccessPort()`

### 2. Security Helpers
Functions for validating security configurations: passwords, encryption, hardening.
- `hasStrongPasswordType()`, `hasPlaintextPassword()`, `hasServicePasswordEncryption()`

### 3. Management Plane
Functions for management access: SSH, SNMP, AAA, NTP, logging.
- `hasSshVersion2()`, `hasSnmpV3AuthPriv()`, `hasAaaAuthentication()`, `hasNtpAuthentication()`

### 4. Control Plane / Routing
Functions for routing protocols: OSPF, BGP, EIGRP, VRRP, HSRP.
- `hasOspfAuthentication()`, `getBgpNeighborsWithoutAuth()`, `hasBgpTtlSecurity()`

### 5. Data Plane
Functions for forwarding security: uRPF, storm control, DHCP snooping, ARP inspection.
- `hasUrpf()`, `hasDhcpSnooping()`, `hasPortSecurity()`, `hasStormControl()`

### 6. Node Navigation
Functions for traversing configuration trees: finding stanzas, child commands, values.
- `findStanza()`, `hasChildCommand()`, `getChildCommand()`, `getParamValue()`

## See Also

- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - Complete guide to writing rules
- [Package Exports](../../packages/core/package.json) - All available import paths

# NVIDIA Cumulus Linux Helper Functions Reference

NVIDIA Cumulus Linux helpers provide specialized functions for validating Cumulus Linux switch configurations. These helpers understand Cumulus-specific configuration formats including ifupdown2 interface stanzas, FRRouting BGP configuration, VXLAN/EVPN overlays, and MLAG/CLAG clustering. Cumulus Linux is a network operating system for bare-metal switches that uses standard Linux tools and familiar networking primitives.

## Import Statement

```typescript
import {
  isIfaceStanza,
  isSwitchPort,
  isBondInterface,
  hasBridgePorts,
  hasClagConfig,
  // ... other helpers
} from '@sentriflow/core/helpers/cumulus';
```

Or import everything:

```typescript
import * as cumulus from '@sentriflow/core/helpers/cumulus';
```

---

## Categories

### 1. Command Type Detection

Functions for identifying Cumulus command formats (NCLU, NVUE, ifupdown2).

---

#### isNcluCommand

Check if a node represents an NCLU command (net add/del).

**Signature:**
```typescript
function isNcluCommand(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node to check |

**Returns:** `boolean` - `true` if node starts with `net `.

**Example:**
```typescript
import { isNcluCommand } from '@sentriflow/core/helpers/cumulus';

isNcluCommand(node);  // true if "net add interface swp1..."
```

---

#### isNvueCommand

Check if a node represents an NVUE command (nv set/unset).

**Signature:**
```typescript
function isNvueCommand(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node to check |

**Returns:** `boolean` - `true` if node starts with `nv `.

**Example:**
```typescript
import { isNvueCommand } from '@sentriflow/core/helpers/cumulus';

isNvueCommand(node);  // true if "nv set interface swp1..."
```

---

#### isIfaceStanza

Check if a node represents an ifupdown2 interface stanza.

**Signature:**
```typescript
function isIfaceStanza(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node to check |

**Returns:** `boolean` - `true` if node starts with `iface `.

**Example:**
```typescript
import { isIfaceStanza } from '@sentriflow/core/helpers/cumulus';

isIfaceStanza(node);  // true if "iface swp1..."
```

---

#### isAutoStanza

Check if a node represents an auto interface stanza.

**Signature:**
```typescript
function isAutoStanza(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node to check |

**Returns:** `boolean` - `true` if node starts with `auto `.

**Example:**
```typescript
import { isAutoStanza } from '@sentriflow/core/helpers/cumulus';

isAutoStanza(node);  // true if "auto swp1"
```

---

### 2. Interface Identification

Functions for classifying Cumulus interface types.

---

#### isSwitchPort

Check if interface is a switch port (swpN pattern).

**Signature:**
```typescript
function isSwitchPort(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if matches `swp\d+` pattern.

**Example:**
```typescript
import { isSwitchPort } from '@sentriflow/core/helpers/cumulus';

isSwitchPort('swp1');   // true
isSwitchPort('swp51');  // true
isSwitchPort('eth0');   // false
isSwitchPort('bond0');  // false
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "cumulus.isSwitchPort",
  "args": [{ "$ref": "node.id" }]
}
```

---

#### isBondInterface

Check if interface is a bond interface.

**Signature:**
```typescript
function isBondInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if matches `bond\d+` pattern.

**Example:**
```typescript
import { isBondInterface } from '@sentriflow/core/helpers/cumulus';

isBondInterface('bond0');  // true
isBondInterface('bond10'); // true
isBondInterface('swp1');   // false
```

---

#### isBridgeInterface

Check if interface is a bridge interface.

**Signature:**
```typescript
function isBridgeInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if bridge-related name.

**Detected Patterns:** Contains `bridge`, equals `br_default`, or matches `br\d+`

**Example:**
```typescript
import { isBridgeInterface } from '@sentriflow/core/helpers/cumulus';

isBridgeInterface('bridge');      // true
isBridgeInterface('br_default');  // true
isBridgeInterface('br0');         // true
isBridgeInterface('swp1');        // false
```

---

#### isVlanInterface

Check if interface is a VLAN interface (SVI).

**Signature:**
```typescript
function isVlanInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if VLAN SVI.

**Detected Patterns:** `vlan\d+` or `_vlan\d+$` suffix

**Example:**
```typescript
import { isVlanInterface } from '@sentriflow/core/helpers/cumulus';

isVlanInterface('vlan100');        // true
isVlanInterface('bridge_vlan10');  // true
isVlanInterface('swp1');           // false
```

---

#### isManagementInterface

Check if interface is the management interface.

**Signature:**
```typescript
function isManagementInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if `eth0` or `mgmt`.

**Example:**
```typescript
import { isManagementInterface } from '@sentriflow/core/helpers/cumulus';

isManagementInterface('eth0');  // true
isManagementInterface('mgmt');  // true
isManagementInterface('swp1');  // false
```

---

#### isLoopback

Check if interface is a loopback.

**Signature:**
```typescript
function isLoopback(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if loopback interface.

**Detected Patterns:** `lo` or starts with `loopback`

**Example:**
```typescript
import { isLoopback } from '@sentriflow/core/helpers/cumulus';

isLoopback('lo');        // true
isLoopback('loopback0'); // true
isLoopback('swp1');      // false
```

---

#### isPeerlink

Check if interface is a peerlink (MLAG).

**Signature:**
```typescript
function isPeerlink(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if name contains `peerlink`.

**Example:**
```typescript
import { isPeerlink } from '@sentriflow/core/helpers/cumulus';

isPeerlink('peerlink');       // true
isPeerlink('peerlink.4094');  // true
isPeerlink('bond0');          // false
```

---

#### isUplinkInterface

Check if interface is an uplink (swp5x pattern common for spine uplinks).

**Signature:**
```typescript
function isUplinkInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if matches uplink pattern.

**Common Patterns:** `swp51`, `swp52`, `swp53`, `swp54` for spine uplinks

**Example:**
```typescript
import { isUplinkInterface } from '@sentriflow/core/helpers/cumulus';

isUplinkInterface('swp51');  // true
isUplinkInterface('swp52');  // true
isUplinkInterface('swp1');   // false
```

---

#### isVniInterface

Check if interface is a VNI (VXLAN) interface.

**Signature:**
```typescript
function isVniInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if VNI interface.

**Detected Patterns:** `vni\d+` or `vni[a-zA-Z]+`

**Example:**
```typescript
import { isVniInterface } from '@sentriflow/core/helpers/cumulus';

isVniInterface('vni10');     // true
isVniInterface('vniRED');    // true
isVniInterface('vxlan100');  // false
```

---

### 3. Interface Configuration Helpers

Functions for checking interface settings.

---

#### getInterfaceName

Get interface name from an iface or auto stanza.

**Signature:**
```typescript
function getInterfaceName(node: ConfigNode): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The iface or auto stanza node |

**Returns:** `string` - The interface name.

**Example:**
```typescript
import { getInterfaceName } from '@sentriflow/core/helpers/cumulus';

// For node with id "iface swp1 inet static"
getInterfaceName(node);  // Returns "swp1"
```

---

#### hasAddress

Check if interface has an IP address configured.

**Signature:**
```typescript
function hasAddress(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if `address` is configured.

**Example:**
```typescript
import { hasAddress } from '@sentriflow/core/helpers/cumulus';

if (hasAddress(interfaceNode)) {
  // Interface has an IP address assigned
}
```

---

#### hasDescription

Check if interface has a description/alias configured.

**Signature:**
```typescript
function hasDescription(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if `alias` is configured.

**Example:**
```typescript
import { hasDescription } from '@sentriflow/core/helpers/cumulus';

if (!hasDescription(interfaceNode)) {
  return { passed: false, message: 'Interface should have a description' };
}
```

---

#### hasMtu

Check if interface has MTU configured.

**Signature:**
```typescript
function hasMtu(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if `mtu` is configured.

**Example:**
```typescript
import { hasMtu } from '@sentriflow/core/helpers/cumulus';

if (!hasMtu(interfaceNode)) {
  // Using default MTU
}
```

---

#### getMtu

Get MTU value from interface.

**Signature:**
```typescript
function getMtu(node: ConfigNode): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `number | null` - MTU value or `null` if not configured.

**Example:**
```typescript
import { getMtu } from '@sentriflow/core/helpers/cumulus';

const mtu = getMtu(interfaceNode);
if (mtu && mtu < 9000) {
  return { passed: false, message: 'Consider jumbo frames for VXLAN' };
}
```

---

#### hasLinkSpeed

Check if interface has link-speed configured.

**Signature:**
```typescript
function hasLinkSpeed(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if `link-speed` is configured.

**Example:**
```typescript
import { hasLinkSpeed } from '@sentriflow/core/helpers/cumulus';

if (hasLinkSpeed(interfaceNode)) {
  // Speed is explicitly set (not auto-negotiated)
}
```

---

#### parseCumulusAddress

Parse Cumulus address format (e.g., "10.0.0.1/24").

**Signature:**
```typescript
function parseCumulusAddress(address: string): { ip: number; prefix: number; mask: number } | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| address | `string` | The address in CIDR notation |

**Returns:** `{ ip: number; prefix: number; mask: number } | null` - Parsed address or `null` if invalid.

**Example:**
```typescript
import { parseCumulusAddress } from '@sentriflow/core/helpers/cumulus';

const addr = parseCumulusAddress('10.0.0.1/24');
// Returns { ip: 167772161, prefix: 24, mask: 4294967040 }
```

---

### 4. Bridge Configuration Helpers

Functions for validating bridge settings.

---

#### isVlanAwareBridge

Check if an iface stanza has VLAN-aware bridge configuration.

**Signature:**
```typescript
function isVlanAwareBridge(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The bridge interface stanza node |

**Returns:** `boolean` - `true` if `bridge-vlan-aware yes` is configured.

**Example:**
```typescript
import { isVlanAwareBridge } from '@sentriflow/core/helpers/cumulus';

if (isVlanAwareBridge(bridgeNode)) {
  // Modern VLAN-aware bridge mode
}
```

---

#### hasBridgePorts

Check if bridge has bridge-ports configured.

**Signature:**
```typescript
function hasBridgePorts(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The bridge interface stanza node |

**Returns:** `boolean` - `true` if `bridge-ports` is configured.

**Example:**
```typescript
import { hasBridgePorts } from '@sentriflow/core/helpers/cumulus';

if (!hasBridgePorts(bridgeNode)) {
  return { passed: false, message: 'Bridge has no member ports' };
}
```

---

#### hasBridgeVids

Check if bridge has bridge-vids (VLANs) configured.

**Signature:**
```typescript
function hasBridgeVids(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The bridge or interface stanza node |

**Returns:** `boolean` - `true` if `bridge-vids` is configured.

**Example:**
```typescript
import { hasBridgeVids } from '@sentriflow/core/helpers/cumulus';

if (!hasBridgeVids(interfaceNode)) {
  // Interface is not trunking any VLANs
}
```

---

#### getBridgeAccessVlan

Get bridge-access VLAN ID from interface.

**Signature:**
```typescript
function getBridgeAccessVlan(node: ConfigNode): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `number | null` - Access VLAN ID or `null` if not configured.

**Example:**
```typescript
import { getBridgeAccessVlan } from '@sentriflow/core/helpers/cumulus';

const vlan = getBridgeAccessVlan(interfaceNode);
if (vlan === 1) {
  return { passed: false, message: 'Avoid using VLAN 1' };
}
```

---

#### getBridgeVids

Get bridge-vids VLANs from bridge interface.

**Signature:**
```typescript
function getBridgeVids(node: ConfigNode): number[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `number[]` - Array of VLAN IDs.

**Example:**
```typescript
import { getBridgeVids } from '@sentriflow/core/helpers/cumulus';

const vlans = getBridgeVids(interfaceNode);
// Returns [10, 20, 30] for "bridge-vids 10 20 30"
```

---

#### getBridgePvid

Get bridge-pvid (native VLAN) from bridge interface.

**Signature:**
```typescript
function getBridgePvid(node: ConfigNode): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `number | null` - Native VLAN ID or `null` if not configured.

**Example:**
```typescript
import { getBridgePvid } from '@sentriflow/core/helpers/cumulus';

const pvid = getBridgePvid(interfaceNode);
if (pvid === 1) {
  return { passed: false, message: 'Change native VLAN from default' };
}
```

---

### 5. Bond Configuration Helpers

Functions for validating bond/LAG settings.

---

#### hasBondSlaves

Check if bond has bond-slaves configured.

**Signature:**
```typescript
function hasBondSlaves(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The bond interface stanza node |

**Returns:** `boolean` - `true` if `bond-slaves` is configured.

**Example:**
```typescript
import { hasBondSlaves } from '@sentriflow/core/helpers/cumulus';

if (!hasBondSlaves(bondNode)) {
  return { passed: false, message: 'Bond has no member interfaces' };
}
```

---

#### hasClagId

Check if bond has clag-id configured.

**Signature:**
```typescript
function hasClagId(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The bond interface stanza node |

**Returns:** `boolean` - `true` if `clag-id` is configured.

**Example:**
```typescript
import { hasClagId, isBondInterface, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isBondInterface(getInterfaceName(node)) && !hasClagId(node)) {
  // Bond is not part of MLAG
}
```

---

### 6. STP Helpers

Functions for validating Spanning Tree Protocol settings.

---

#### hasBpduGuard

Check if interface has STP bpdu-guard enabled.

**Signature:**
```typescript
function hasBpduGuard(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if bpduguard is set to yes.

**Example:**
```typescript
import { hasBpduGuard, hasPortAdminEdge } from '@sentriflow/core/helpers/cumulus';

if (hasPortAdminEdge(node) && !hasBpduGuard(node)) {
  return { passed: false, message: 'Enable BPDU guard on edge ports' };
}
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "cumulus.hasBpduGuard",
  "args": [{ "$ref": "node" }],
  "negate": true
}
```

---

#### hasPortAdminEdge

Check if interface has STP portadminedge (portfast equivalent).

**Signature:**
```typescript
function hasPortAdminEdge(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if portadminedge is set to yes.

**Example:**
```typescript
import { hasPortAdminEdge } from '@sentriflow/core/helpers/cumulus';

if (hasPortAdminEdge(interfaceNode)) {
  // This is an edge port - check for BPDU guard
}
```

---

#### hasRootGuard

Check if root guard (portrestrictedtcn) is enabled.

**Signature:**
```typescript
function hasRootGuard(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if portrestrictedtcn is set to yes.

**Example:**
```typescript
import { hasRootGuard } from '@sentriflow/core/helpers/cumulus';

if (!hasRootGuard(interfaceNode)) {
  return { passed: false, message: 'Consider enabling root guard' };
}
```

---

#### hasPortBpduFilter

Check if mstpctl-portbpdufilter is enabled on VNI.

**Signature:**
```typescript
function hasPortBpduFilter(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VNI interface stanza node |

**Returns:** `boolean` - `true` if portbpdufilter is set to yes.

**Example:**
```typescript
import { hasPortBpduFilter, isVniInterface, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isVniInterface(getInterfaceName(node)) && !hasPortBpduFilter(node)) {
  // VNI should have BPDU filter enabled
}
```

---

### 7. MLAG/CLAG Helpers

Functions for validating Multi-Chassis Link Aggregation settings.

---

#### hasClagConfig

Check if CLAG/MLAG is configured in an interface.

**Signature:**
```typescript
function hasClagConfig(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if any clag configuration present.

**Example:**
```typescript
import { hasClagConfig } from '@sentriflow/core/helpers/cumulus';

if (hasClagConfig(interfaceNode)) {
  // Interface is part of MLAG configuration
}
```

---

#### isPeerlinkSubinterface

Check if peerlink.4094 sub-interface for CLAG control.

**Signature:**
```typescript
function isPeerlinkSubinterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if peerlink.4094 control interface.

**Example:**
```typescript
import { isPeerlinkSubinterface } from '@sentriflow/core/helpers/cumulus';

isPeerlinkSubinterface('peerlink.4094');  // true
isPeerlinkSubinterface('peerlink');       // false
```

---

#### hasClagdPeerIp

Check if clagd-peer-ip is configured.

**Signature:**
```typescript
function hasClagdPeerIp(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The peerlink.4094 interface stanza node |

**Returns:** `boolean` - `true` if `clagd-peer-ip` is configured.

**Example:**
```typescript
import { hasClagdPeerIp, isPeerlinkSubinterface, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isPeerlinkSubinterface(getInterfaceName(node)) && !hasClagdPeerIp(node)) {
  return { passed: false, message: 'MLAG requires clagd-peer-ip' };
}
```

---

#### hasClagdBackupIp

Check if clagd-backup-ip is configured.

**Signature:**
```typescript
function hasClagdBackupIp(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The peerlink.4094 interface stanza node |

**Returns:** `boolean` - `true` if `clagd-backup-ip` is configured.

**Example:**
```typescript
import { hasClagdBackupIp } from '@sentriflow/core/helpers/cumulus';

if (!hasClagdBackupIp(peerlinkNode)) {
  return { passed: false, message: 'Configure backup IP for MLAG resilience' };
}
```

---

#### hasClagdSysMac

Check if clagd-sys-mac is configured.

**Signature:**
```typescript
function hasClagdSysMac(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The peerlink.4094 interface stanza node |

**Returns:** `boolean` - `true` if `clagd-sys-mac` is configured.

**Example:**
```typescript
import { hasClagdSysMac } from '@sentriflow/core/helpers/cumulus';

if (!hasClagdSysMac(peerlinkNode)) {
  return { passed: false, message: 'MLAG requires clagd-sys-mac' };
}
```

---

#### isValidClagdSysMac

Validate clagd-sys-mac is in reserved range 44:38:39:ff:xx:xx.

**Signature:**
```typescript
function isValidClagdSysMac(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The peerlink.4094 interface stanza node |

**Returns:** `boolean` - `true` if MAC is in valid reserved range.

**Valid Ranges:** `44:38:39:ff:xx:xx` or `44:38:39:be:ef:xx` (legacy)

**Example:**
```typescript
import { isValidClagdSysMac, hasClagdSysMac } from '@sentriflow/core/helpers/cumulus';

if (hasClagdSysMac(node) && !isValidClagdSysMac(node)) {
  return { passed: false, message: 'Use reserved MAC range 44:38:39:ff:xx:xx' };
}
```

---

#### hasClagdPriority

Check if clagd-priority is configured.

**Signature:**
```typescript
function hasClagdPriority(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The peerlink.4094 interface stanza node |

**Returns:** `boolean` - `true` if `clagd-priority` is configured.

**Example:**
```typescript
import { hasClagdPriority } from '@sentriflow/core/helpers/cumulus';

if (!hasClagdPriority(peerlinkNode)) {
  // Using default priority - consider explicit configuration
}
```

---

#### hasVrrConfig

Check if VRR (Virtual Router Redundancy) is configured.

**Signature:**
```typescript
function hasVrrConfig(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SVI interface stanza node |

**Returns:** `boolean` - `true` if `address-virtual` is configured.

**Example:**
```typescript
import { hasVrrConfig, isVlanInterface, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isVlanInterface(getInterfaceName(node)) && !hasVrrConfig(node)) {
  // Consider VRR for gateway redundancy
}
```

---

### 8. Management Plane Helpers

Functions for validating management access configuration.

---

#### hasManagementVrf

Check if management interface is in management VRF.

**Signature:**
```typescript
function hasManagementVrf(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if `vrf mgmt` is configured.

**Example:**
```typescript
import { hasManagementVrf, isManagementInterface, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isManagementInterface(getInterfaceName(node)) && !hasManagementVrf(node)) {
  return { passed: false, message: 'Place management interface in mgmt VRF' };
}
```

---

#### isManagementVrf

Check if a VRF stanza is management VRF.

**Signature:**
```typescript
function isManagementVrf(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The VRF name |

**Returns:** `boolean` - `true` if VRF name is `mgmt`.

**Example:**
```typescript
import { isManagementVrf } from '@sentriflow/core/helpers/cumulus';

isManagementVrf('mgmt');     // true
isManagementVrf('default');  // false
```

---

### 9. VXLAN/EVPN Helpers

Functions for validating VXLAN and EVPN overlay configuration.

---

#### hasEvpnConfig

Check if EVPN is configured.

**Signature:**
```typescript
function hasEvpnConfig(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP address-family node |

**Returns:** `boolean` - `true` if L2VPN EVPN or advertise-all-vni configured.

**Example:**
```typescript
import { hasEvpnConfig } from '@sentriflow/core/helpers/cumulus';

if (hasEvpnConfig(bgpNode)) {
  // EVPN is enabled - validate VNI configuration
}
```

---

#### hasVxlanLocalTunnelip

Check if vxlan-local-tunnelip is configured on loopback.

**Signature:**
```typescript
function hasVxlanLocalTunnelip(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The loopback interface stanza node |

**Returns:** `boolean` - `true` if `vxlan-local-tunnelip` is configured.

**Example:**
```typescript
import { hasVxlanLocalTunnelip, isLoopback, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isLoopback(getInterfaceName(node)) && !hasVxlanLocalTunnelip(node)) {
  return { passed: false, message: 'Configure VTEP source IP on loopback' };
}
```

---

#### hasVxlanAnycastIp

Check if clagd-vxlan-anycast-ip is configured for MLAG+VXLAN.

**Signature:**
```typescript
function hasVxlanAnycastIp(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The loopback interface stanza node |

**Returns:** `boolean` - `true` if `clagd-vxlan-anycast-ip` is configured.

**Example:**
```typescript
import { hasVxlanAnycastIp, hasClagConfig } from '@sentriflow/core/helpers/cumulus';

// For MLAG+VXLAN deployments
if (hasClagConfig(peerlinkNode) && !hasVxlanAnycastIp(loopbackNode)) {
  return { passed: false, message: 'Configure VXLAN anycast IP for MLAG' };
}
```

---

#### hasVxlanId

Check if vxlan-id is configured.

**Signature:**
```typescript
function hasVxlanId(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VNI interface stanza node |

**Returns:** `boolean` - `true` if `vxlan-id` is configured.

**Example:**
```typescript
import { hasVxlanId, isVniInterface, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isVniInterface(getInterfaceName(node)) && !hasVxlanId(node)) {
  return { passed: false, message: 'VNI interface requires vxlan-id' };
}
```

---

#### hasArpNdSuppress

Check if bridge-arp-nd-suppress is enabled on VNI.

**Signature:**
```typescript
function hasArpNdSuppress(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VNI interface stanza node |

**Returns:** `boolean` - `true` if ARP/ND suppression is enabled.

**Example:**
```typescript
import { hasArpNdSuppress } from '@sentriflow/core/helpers/cumulus';

if (!hasArpNdSuppress(vniNode)) {
  return { passed: false, message: 'Enable ARP/ND suppression for EVPN efficiency' };
}
```

---

#### hasBridgeLearningOff

Check if bridge-learning is disabled on VNI.

**Signature:**
```typescript
function hasBridgeLearningOff(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VNI interface stanza node |

**Returns:** `boolean` - `true` if bridge learning is off.

**Example:**
```typescript
import { hasBridgeLearningOff, isVniInterface, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isVniInterface(getInterfaceName(node)) && !hasBridgeLearningOff(node)) {
  return { passed: false, message: 'Disable bridge learning on VNI for EVPN' };
}
```

---

### 10. BGP Helpers

Functions for validating BGP routing configuration.

---

#### hasBgpRouterId

Check if a router bgp block has router-id configured.

**Signature:**
```typescript
function hasBgpRouterId(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |

**Returns:** `boolean` - `true` if `bgp router-id` is configured.

**Example:**
```typescript
import { hasBgpRouterId } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpRouterId(routerBgpNode)) {
  return { passed: false, message: 'Explicitly configure BGP router-id' };
}
```

---

#### hasBgpNeighbors

Check if a router bgp block has neighbors configured.

**Signature:**
```typescript
function hasBgpNeighbors(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |

**Returns:** `boolean` - `true` if `neighbor` commands are present.

**Example:**
```typescript
import { hasBgpNeighbors } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpNeighbors(routerBgpNode)) {
  // BGP is configured but has no peers
}
```

---

#### getBgpNeighborAddress

Get BGP neighbor address/interface from a neighbor command.

**Signature:**
```typescript
function getBgpNeighborAddress(neighborCmd: string): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| neighborCmd | `string` | The neighbor command string |

**Returns:** `string` - The neighbor address or interface name.

**Example:**
```typescript
import { getBgpNeighborAddress } from '@sentriflow/core/helpers/cumulus';

getBgpNeighborAddress('neighbor 10.0.0.1 remote-as 65001');
// Returns "10.0.0.1"

getBgpNeighborAddress('neighbor swp51 interface remote-as external');
// Returns "swp51"
```

---

#### getBgpPeerGroups

Get BGP peer groups from router bgp block.

**Signature:**
```typescript
function getBgpPeerGroups(node: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |

**Returns:** `string[]` - Array of peer group names.

**Example:**
```typescript
import { getBgpPeerGroups } from '@sentriflow/core/helpers/cumulus';

const peerGroups = getBgpPeerGroups(routerBgpNode);
// Returns ["fabric", "external"] for defined peer-groups
```

---

#### hasBgpNeighborPassword

Check if BGP authentication (password) is configured for a neighbor.

**Signature:**
```typescript
function hasBgpNeighborPassword(node: ConfigNode, neighborAddr: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |
| neighborAddr | `string` | The neighbor address or peer-group name |

**Returns:** `boolean` - `true` if password is configured.

**Example:**
```typescript
import { hasBgpNeighborPassword } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpNeighborPassword(routerBgpNode, '10.0.0.1')) {
  return { passed: false, message: 'Configure BGP authentication' };
}
```

---

#### hasBgpPeerGroupPassword

Check if BGP peer-group has password configured.

**Signature:**
```typescript
function hasBgpPeerGroupPassword(node: ConfigNode, peerGroup: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |
| peerGroup | `string` | The peer-group name |

**Returns:** `boolean` - `true` if password is configured for peer-group.

**Example:**
```typescript
import { hasBgpPeerGroupPassword } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpPeerGroupPassword(routerBgpNode, 'external')) {
  return { passed: false, message: 'Configure password on external peer-group' };
}
```

---

#### hasBgpMaximumPrefix

Check if BGP maximum-prefix is configured for neighbor.

**Signature:**
```typescript
function hasBgpMaximumPrefix(node: ConfigNode, neighborAddr: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |
| neighborAddr | `string` | The neighbor address |

**Returns:** `boolean` - `true` if maximum-prefix is configured.

**Example:**
```typescript
import { hasBgpMaximumPrefix } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpMaximumPrefix(routerBgpNode, '10.0.0.1')) {
  return { passed: false, message: 'Set maximum-prefix to prevent route leaks' };
}
```

---

#### hasBgpBfd

Check if BFD is enabled for BGP neighbor.

**Signature:**
```typescript
function hasBgpBfd(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |

**Returns:** `boolean` - `true` if BFD is configured for any neighbor.

**Example:**
```typescript
import { hasBgpBfd } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpBfd(routerBgpNode)) {
  return { passed: false, message: 'Consider enabling BFD for fast failover' };
}
```

---

#### hasBgpMultipath

Check if BGP multipath is configured.

**Signature:**
```typescript
function hasBgpMultipath(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |

**Returns:** `boolean` - `true` if multipath-relax or maximum-paths configured.

**Example:**
```typescript
import { hasBgpMultipath } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpMultipath(routerBgpNode)) {
  // Consider enabling ECMP for load balancing
}
```

---

#### hasBgpPrefixListIn

Check if prefix-list is applied to BGP neighbor (inbound).

**Signature:**
```typescript
function hasBgpPrefixListIn(node: ConfigNode, neighborOrGroup: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |
| neighborOrGroup | `string` | The neighbor address or peer-group name |

**Returns:** `boolean` - `true` if inbound prefix-list is applied.

**Example:**
```typescript
import { hasBgpPrefixListIn } from '@sentriflow/core/helpers/cumulus';

if (!hasBgpPrefixListIn(routerBgpNode, 'external')) {
  return { passed: false, message: 'Apply inbound prefix-list to filter routes' };
}
```

---

### 11. Configuration Search Helpers

Functions for finding configuration elements.

---

#### findIfaceStanzas

Find all iface stanzas in a configuration tree.

**Signature:**
```typescript
function findIfaceStanzas(root: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| root | `ConfigNode` | The root configuration node |

**Returns:** `ConfigNode[]` - Array of all iface stanza nodes.

**Example:**
```typescript
import { findIfaceStanzas, isSwitchPort, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

const allInterfaces = findIfaceStanzas(configRoot);
const switchPorts = allInterfaces.filter(node =>
  isSwitchPort(getInterfaceName(node))
);
```

---

#### findStanza

Find a stanza by name within a node's children.

**Signature:**
```typescript
function findStanza(node: ConfigNode, stanzaName: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| stanzaName | `string` | The exact stanza name to find |

**Returns:** `ConfigNode | undefined` - The matching stanza or undefined.

**Example:**
```typescript
import { findStanza } from '@sentriflow/core/helpers/cumulus';

const bridgeStanza = findStanza(root, 'iface bridge');
```

---

#### findStanzasByPrefix

Find all stanzas starting with a prefix.

**Signature:**
```typescript
function findStanzasByPrefix(node: ConfigNode, prefix: string): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| prefix | `string` | The prefix to match |

**Returns:** `ConfigNode[]` - Array of matching stanza nodes.

**Example:**
```typescript
import { findStanzasByPrefix } from '@sentriflow/core/helpers/cumulus';

const allIfaceStanzas = findStanzasByPrefix(root, 'iface ');
const allAutoStanzas = findStanzasByPrefix(root, 'auto ');
```

---

### 12. Security Helpers

Functions for validating security configurations.

---

#### hasStormControl

Check if storm control is configured on interface.

**Signature:**
```typescript
function hasStormControl(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if storm-control is configured.

**Example:**
```typescript
import { hasStormControl, isSwitchPort, getInterfaceName } from '@sentriflow/core/helpers/cumulus';

if (isSwitchPort(getInterfaceName(node)) && !hasStormControl(node)) {
  return { passed: false, message: 'Consider enabling storm control' };
}
```

---

#### hasPortIsolation

Check if bridge-port-isolation is enabled.

**Signature:**
```typescript
function hasPortIsolation(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface stanza node |

**Returns:** `boolean` - `true` if port isolation is on.

**Example:**
```typescript
import { hasPortIsolation } from '@sentriflow/core/helpers/cumulus';

if (hasPortIsolation(interfaceNode)) {
  // Interface is isolated from other ports in same VLAN
}
```

---

## See Also

- [Common Helpers](./common.md) - Shared helper functions used across vendors
- [Cisco Helpers](./cisco.md) - Cisco IOS/IOS-XE helper functions
- [Arista Helpers](./arista.md) - Arista EOS helper functions
- [Juniper Helpers](./juniper.md) - Juniper Junos helper functions
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - Complete guide to writing validation rules

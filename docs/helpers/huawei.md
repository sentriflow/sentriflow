# Huawei VRP Helper Functions Reference

Huawei helpers provide specialized functions for validating Huawei VRP (Versatile Routing Platform) router and switch configurations. These helpers understand Huawei-specific syntax, including the `undo` command pattern for negation, VRP command structures, and security best practices for Huawei devices.

## Platform Notes

Huawei VRP uses a distinct configuration style compared to other vendors:
- **Shutdown behavior**: Interfaces are shutdown by default; use `undo shutdown` to enable
- **Negation pattern**: Commands are disabled using the `undo` prefix (e.g., `undo lldp enable`)
- **Interface naming**: Uses `Vlanif` for VLAN interfaces, `Eth-Trunk` for LAGs
- **Port types**: Supports access, trunk, and hybrid port modes

## Import Statement

```typescript
import {
  isShutdown,
  isEnabled,
  isPhysicalPort,
  isTrunkPort,
  hasOspfAreaAuthentication,
  getBgpPeers,
  // ... other helpers
} from '@sentriflow/core/helpers/huawei';
```

Or import everything:

```typescript
import * as huawei from '@sentriflow/core/helpers/huawei';
```

---

## Categories

### 1. Interface Identification

Functions for classifying Huawei interface types and states.

---

### isShutdown

Check if interface is shutdown. In Huawei VRP, interfaces are shutdown by default and require `undo shutdown` to enable.

**Signature:**
```typescript
function isShutdown(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if interface is shutdown (default) or has explicit `shutdown` command; `false` if `undo shutdown` is present.

**Example:**
```typescript
import { isShutdown } from '@sentriflow/core/helpers/huawei';

if (isShutdown(interfaceNode)) {
  return { passed: true, message: 'Interface is shutdown - skipping' };
}
```

---

### isEnabled

Check if interface is explicitly enabled (has `undo shutdown`).

**Signature:**
```typescript
function isEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if interface has `undo shutdown` command.

**Example:**
```typescript
import { isEnabled } from '@sentriflow/core/helpers/huawei';

if (isEnabled(interfaceNode)) {
  // Apply security checks to active interfaces
}
```

---

### isPhysicalPort

Check if interface is a physical port (not Vlanif, LoopBack, NULL, Tunnel, etc.).

**Signature:**
```typescript
function isPhysicalPort(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface identifier from node.id |

**Returns:** `boolean` - `true` if physical port, `false` for virtual interfaces.

**Excluded Types:** Vlanif, LoopBack, NULL, Tunnel, Eth-Trunk, NVE, Vbdif

**Example:**
```typescript
import { isPhysicalPort } from '@sentriflow/core/helpers/huawei';

isPhysicalPort('GigabitEthernet0/0/1');  // true
isPhysicalPort('interface Vlanif100');    // false
isPhysicalPort('interface LoopBack0');    // false
isPhysicalPort('interface Eth-Trunk1');   // false
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "huawei.isPhysicalPort",
  "args": [{ "$ref": "node.id" }]
}
```

---

### isVlanInterface

Check if interface is a VLAN interface (Vlanif).

**Signature:**
```typescript
function isVlanInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if Vlanif interface.

**Example:**
```typescript
import { isVlanInterface } from '@sentriflow/core/helpers/huawei';

isVlanInterface('interface Vlanif100');       // true
isVlanInterface('interface GigabitEthernet0/0/1'); // false
```

---

### isLoopbackInterface

Check if interface is a loopback interface.

**Signature:**
```typescript
function isLoopbackInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if loopback interface.

**Example:**
```typescript
import { isLoopbackInterface } from '@sentriflow/core/helpers/huawei';

isLoopbackInterface('LoopBack0');              // true
isLoopbackInterface('GigabitEthernet0/0/1');   // false
```

---

### isEthTrunk

Check if interface is an Eth-Trunk (Link Aggregation Group).

**Signature:**
```typescript
function isEthTrunk(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if Eth-Trunk interface.

**Example:**
```typescript
import { isEthTrunk } from '@sentriflow/core/helpers/huawei';

isEthTrunk('Eth-Trunk1');           // true
isEthTrunk('GigabitEthernet0/0/1'); // false
```

---

### isTrunkPort

Check if interface is configured as a trunk port.

**Signature:**
```typescript
function isTrunkPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if has `port link-type trunk`.

**Example:**
```typescript
import { isTrunkPort } from '@sentriflow/core/helpers/huawei';

if (isTrunkPort(interfaceNode)) {
  // Check trunk-specific security settings
}
```

---

### isAccessPort

Check if interface is configured as an access port.

**Signature:**
```typescript
function isAccessPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if has `port link-type access`.

**Example:**
```typescript
import { isAccessPort } from '@sentriflow/core/helpers/huawei';

if (isAccessPort(interfaceNode)) {
  // Check access port security settings
}
```

---

### isHybridPort

Check if interface is configured as a hybrid port. Hybrid ports can carry both tagged and untagged VLANs.

**Signature:**
```typescript
function isHybridPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if has `port link-type hybrid`.

**Example:**
```typescript
import { isHybridPort } from '@sentriflow/core/helpers/huawei';

if (isHybridPort(interfaceNode)) {
  // Hybrid port-specific validation
}
```

---

### 2. VLAN Configuration

Functions for extracting VLAN settings from interface configurations.

---

### getDefaultVlan

Get the default VLAN for an access port.

**Signature:**
```typescript
function getDefaultVlan(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `string | undefined` - VLAN ID or `undefined` if not configured.

**Example:**
```typescript
import { getDefaultVlan, isAccessPort } from '@sentriflow/core/helpers/huawei';

if (isAccessPort(interfaceNode)) {
  const vlan = getDefaultVlan(interfaceNode);
  if (vlan === '1') {
    return { passed: false, message: 'Access port using default VLAN 1' };
  }
}
```

---

### getTrunkAllowedVlans

Get allowed VLANs for a trunk port.

**Signature:**
```typescript
function getTrunkAllowedVlans(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `string | undefined` - VLAN list string or `undefined` if not configured.

**Example:**
```typescript
import { getTrunkAllowedVlans, isTrunkPort } from '@sentriflow/core/helpers/huawei';

if (isTrunkPort(interfaceNode)) {
  const vlans = getTrunkAllowedVlans(interfaceNode);
  if (vlans?.toLowerCase() === 'all') {
    return { passed: false, message: 'Trunk allows all VLANs - prune unused VLANs' };
  }
}
```

---

### 3. Interface Documentation

Functions for managing interface descriptions.

---

### hasDescription

Check if interface has a description configured.

**Signature:**
```typescript
function hasDescription(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if description is present.

**Example:**
```typescript
import { hasDescription, isEnabled } from '@sentriflow/core/helpers/huawei';

if (isEnabled(interfaceNode) && !hasDescription(interfaceNode)) {
  return { passed: false, message: 'Active interface should have a description' };
}
```

---

### getDescription

Get the interface description text.

**Signature:**
```typescript
function getDescription(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `string | undefined` - Description text or `undefined` if not configured.

**Example:**
```typescript
import { getDescription } from '@sentriflow/core/helpers/huawei';

const desc = getDescription(interfaceNode);
if (desc?.toLowerCase().includes('uplink')) {
  // Apply uplink-specific rules
}
```

---

### 4. Layer 2 Security

Functions for validating Layer 2 security features like STP and port security.

---

### hasStpEdgedPort

Check if STP edge port is enabled (`stp edged-port enable`).

**Signature:**
```typescript
function hasStpEdgedPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if STP edged-port is enabled.

**Example:**
```typescript
import { hasStpEdgedPort, isAccessPort } from '@sentriflow/core/helpers/huawei';

if (isAccessPort(interfaceNode) && !hasStpEdgedPort(interfaceNode)) {
  return { passed: false, message: 'Access port should have stp edged-port enable' };
}
```

---

### hasPortSecurity

Check if port security is enabled on the interface.

**Signature:**
```typescript
function hasPortSecurity(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `port-security enable` is configured.

**Example:**
```typescript
import { hasPortSecurity } from '@sentriflow/core/helpers/huawei';

if (!hasPortSecurity(interfaceNode)) {
  return { passed: false, message: 'Enable port-security on edge ports' };
}
```

---

### hasBpduProtection

Check if BPDU protection is enabled on the interface.

**Signature:**
```typescript
function hasBpduProtection(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if BPDU protection is configured.

**Checks for:** `stp bpdu-protection` or `bpdu-protection enable`

**Example:**
```typescript
import { hasBpduProtection, isAccessPort } from '@sentriflow/core/helpers/huawei';

if (isAccessPort(interfaceNode) && !hasBpduProtection(interfaceNode)) {
  return { passed: false, message: 'Enable BPDU protection on access ports' };
}
```

---

### 5. Management Plane

Functions for validating management access security on user-interfaces and local users.

---

### isSshEnabled

Check if SSH is enabled on a user-interface.

**Signature:**
```typescript
function isSshEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The user-interface node |

**Returns:** `boolean` - `true` if `protocol inbound ssh` or `protocol inbound all` is configured.

**Example:**
```typescript
import { isSshEnabled } from '@sentriflow/core/helpers/huawei';

if (!isSshEnabled(vtyNode)) {
  return { passed: false, message: 'SSH should be enabled on VTY lines' };
}
```

---

### isTelnetEnabled

Check if Telnet is enabled on a user-interface (security concern).

**Signature:**
```typescript
function isTelnetEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The user-interface node |

**Returns:** `boolean` - `true` if Telnet is enabled or is the default.

**Example:**
```typescript
import { isTelnetEnabled } from '@sentriflow/core/helpers/huawei';

if (isTelnetEnabled(vtyNode)) {
  return { passed: false, message: 'Disable Telnet - use SSH instead' };
}
```

---

### hasAaaAuthentication

Check if AAA authentication mode is configured on user-interface.

**Signature:**
```typescript
function hasAaaAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The user-interface node |

**Returns:** `boolean` - `true` if `authentication-mode aaa` is configured.

**Example:**
```typescript
import { hasAaaAuthentication } from '@sentriflow/core/helpers/huawei';

if (!hasAaaAuthentication(vtyNode)) {
  return { passed: false, message: 'Use AAA authentication mode' };
}
```

---

### hasPasswordAuthentication

Check if password authentication is configured (less secure than AAA).

**Signature:**
```typescript
function hasPasswordAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The user-interface node |

**Returns:** `boolean` - `true` if `authentication-mode password` is configured.

**Example:**
```typescript
import { hasPasswordAuthentication } from '@sentriflow/core/helpers/huawei';

if (hasPasswordAuthentication(vtyNode)) {
  return { passed: false, message: 'Upgrade to AAA authentication' };
}
```

---

### hasIdleTimeout

Check if idle timeout is configured on user-interface.

**Signature:**
```typescript
function hasIdleTimeout(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The user-interface node |

**Returns:** `boolean` - `true` if `idle-timeout` is configured.

**Example:**
```typescript
import { hasIdleTimeout } from '@sentriflow/core/helpers/huawei';

if (!hasIdleTimeout(vtyNode)) {
  return { passed: false, message: 'Configure idle-timeout on VTY lines' };
}
```

---

### getIdleTimeout

Get idle timeout value in minutes.

**Signature:**
```typescript
function getIdleTimeout(node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The user-interface node |

**Returns:** `number | undefined` - Timeout in minutes or `undefined` if not configured.

**Example:**
```typescript
import { getIdleTimeout } from '@sentriflow/core/helpers/huawei';

const timeout = getIdleTimeout(vtyNode);
if (timeout && timeout > 10) {
  return { passed: false, message: 'Idle timeout should be 10 minutes or less' };
}
```

---

### hasAclInbound

Check if ACL is applied inbound on user-interface.

**Signature:**
```typescript
function hasAclInbound(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The user-interface node |

**Returns:** `boolean` - `true` if ACL is applied inbound.

**Example:**
```typescript
import { hasAclInbound } from '@sentriflow/core/helpers/huawei';

if (!hasAclInbound(vtyNode)) {
  return { passed: false, message: 'Apply ACL inbound to restrict management access' };
}
```

---

### hasLoginBanner

Check if login banner is configured.

**Signature:**
```typescript
function hasLoginBanner(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node to check |

**Returns:** `boolean` - `true` if node is a `header login` configuration.

**Example:**
```typescript
import { hasLoginBanner } from '@sentriflow/core/helpers/huawei';

// Use with AST to find if banner is configured
const hasBanner = ast.some(hasLoginBanner);
```

---

### 6. User and Password Security

Functions for validating local user configurations and password security.

---

### hasEncryptedPassword

Check if local-user has password configured with cipher (encrypted).

**Signature:**
```typescript
function hasEncryptedPassword(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The local-user node |

**Returns:** `boolean` - `true` if using `password cipher` or `password irreversible-cipher`.

**Example:**
```typescript
import { hasEncryptedPassword } from '@sentriflow/core/helpers/huawei';

if (!hasEncryptedPassword(localUserNode)) {
  return { passed: false, message: 'User password should be encrypted' };
}
```

---

### hasPlaintextPassword

Check if local-user has plaintext password (security concern).

**Signature:**
```typescript
function hasPlaintextPassword(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The local-user node |

**Returns:** `boolean` - `true` if `password simple` is used.

**Example:**
```typescript
import { hasPlaintextPassword } from '@sentriflow/core/helpers/huawei';

if (hasPlaintextPassword(localUserNode)) {
  return { passed: false, message: 'Never use plaintext passwords' };
}
```

---

### getPrivilegeLevel

Get privilege level for local-user.

**Signature:**
```typescript
function getPrivilegeLevel(node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The local-user node |

**Returns:** `number | undefined` - Privilege level (0-15) or `undefined`.

**Example:**
```typescript
import { getPrivilegeLevel } from '@sentriflow/core/helpers/huawei';

const level = getPrivilegeLevel(localUserNode);
if (level === 15) {
  // Full administrative access - extra scrutiny
}
```

---

### 7. BGP Helpers

Functions for validating BGP configuration and peer security.

---

### getBgpPeers

Get all BGP peer IP addresses from configuration.

**Signature:**
```typescript
function getBgpPeers(node: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP configuration node |

**Returns:** `string[]` - Array of peer IP addresses.

**Example:**
```typescript
import { getBgpPeers, hasBgpPeerPassword } from '@sentriflow/core/helpers/huawei';

const peers = getBgpPeers(bgpNode);
for (const peerIp of peers) {
  if (!hasBgpPeerPassword(bgpNode, peerIp)) {
    // Flag peer without password
  }
}
```

---

### hasBgpPeerPassword

Check if BGP peer has password authentication configured.

**Signature:**
```typescript
function hasBgpPeerPassword(node: ConfigNode, peerIp: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP configuration node |
| peerIp | `string` | The peer IP address |

**Returns:** `boolean` - `true` if password is configured for the peer.

**Example:**
```typescript
import { hasBgpPeerPassword } from '@sentriflow/core/helpers/huawei';

if (!hasBgpPeerPassword(bgpNode, '10.0.0.1')) {
  return { passed: false, message: 'BGP peer 10.0.0.1 lacks authentication' };
}
```

---

### hasBgpPeerKeychain

Check if BGP peer has keychain authentication configured.

**Signature:**
```typescript
function hasBgpPeerKeychain(node: ConfigNode, peerIp: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP configuration node |
| peerIp | `string` | The peer IP address |

**Returns:** `boolean` - `true` if keychain is configured for the peer.

**Example:**
```typescript
import { hasBgpPeerKeychain } from '@sentriflow/core/helpers/huawei';

if (hasBgpPeerKeychain(bgpNode, '10.0.0.1')) {
  // Keychain provides rotating keys - best practice
}
```

---

### hasBgpPeerGtsm

Check if BGP peer has GTSM (valid-ttl-hops) configured.

**Signature:**
```typescript
function hasBgpPeerGtsm(node: ConfigNode, peerIp: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP configuration node |
| peerIp | `string` | The peer IP address |

**Returns:** `boolean` - `true` if GTSM/valid-ttl-hops is configured.

**Example:**
```typescript
import { hasBgpPeerGtsm } from '@sentriflow/core/helpers/huawei';

if (!hasBgpPeerGtsm(bgpNode, '10.0.0.1')) {
  return { passed: false, message: 'Enable GTSM for eBGP peer protection' };
}
```

---

### hasBgpPeerRouteLimit

Check if BGP peer has route-limit (maximum prefix) configured.

**Signature:**
```typescript
function hasBgpPeerRouteLimit(node: ConfigNode, peerIp: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP configuration node |
| peerIp | `string` | The peer IP address |

**Returns:** `boolean` - `true` if route-limit is configured.

**Example:**
```typescript
import { hasBgpPeerRouteLimit } from '@sentriflow/core/helpers/huawei';

if (!hasBgpPeerRouteLimit(bgpNode, '10.0.0.1')) {
  return { passed: false, message: 'Configure route-limit to prevent route table overflow' };
}
```

---

### hasBgpPeerPrefixFilter

Check if BGP peer has prefix filtering configured.

**Signature:**
```typescript
function hasBgpPeerPrefixFilter(node: ConfigNode, peerIp: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP configuration node |
| peerIp | `string` | The peer IP address |

**Returns:** `boolean` - `true` if prefix filtering is configured.

**Checks for:** `ip-prefix`, `route-policy`, or `filter-policy`

**Example:**
```typescript
import { hasBgpPeerPrefixFilter } from '@sentriflow/core/helpers/huawei';

if (!hasBgpPeerPrefixFilter(bgpNode, '10.0.0.1')) {
  return { passed: false, message: 'Apply prefix filtering to BGP peer' };
}
```

---

### hasBgpGracefulRestart

Check if BGP has graceful-restart enabled.

**Signature:**
```typescript
function hasBgpGracefulRestart(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP configuration node |

**Returns:** `boolean` - `true` if graceful-restart is enabled.

**Example:**
```typescript
import { hasBgpGracefulRestart } from '@sentriflow/core/helpers/huawei';

if (!hasBgpGracefulRestart(bgpNode)) {
  // Consider enabling for improved convergence during restarts
}
```

---

### 8. OSPF and IS-IS Helpers

Functions for validating IGP routing protocol security.

---

### hasOspfAreaAuthentication

Check if OSPF area has authentication configured.

**Signature:**
```typescript
function hasOspfAreaAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The OSPF area node |

**Returns:** `boolean` - `true` if `authentication-mode` is configured.

**Example:**
```typescript
import { hasOspfAreaAuthentication } from '@sentriflow/core/helpers/huawei';

if (!hasOspfAreaAuthentication(ospfAreaNode)) {
  return { passed: false, message: 'Enable OSPF area authentication' };
}
```

---

### hasInterfaceOspfAuth

Check if interface has OSPF authentication configured.

**Signature:**
```typescript
function hasInterfaceOspfAuth(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `ospf authentication-mode` is configured.

**Example:**
```typescript
import { hasInterfaceOspfAuth } from '@sentriflow/core/helpers/huawei';

if (!hasInterfaceOspfAuth(interfaceNode)) {
  return { passed: false, message: 'Configure OSPF authentication on interface' };
}
```

---

### hasIsisAreaAuth

Check if IS-IS has area authentication configured.

**Signature:**
```typescript
function hasIsisAreaAuth(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The IS-IS configuration node |

**Returns:** `boolean` - `true` if `area-authentication-mode` is configured.

**Example:**
```typescript
import { hasIsisAreaAuth } from '@sentriflow/core/helpers/huawei';

if (!hasIsisAreaAuth(isisNode)) {
  return { passed: false, message: 'Enable IS-IS area authentication' };
}
```

---

### hasIsisDomainAuth

Check if IS-IS has domain authentication configured.

**Signature:**
```typescript
function hasIsisDomainAuth(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The IS-IS configuration node |

**Returns:** `boolean` - `true` if `domain-authentication-mode` is configured.

**Example:**
```typescript
import { hasIsisDomainAuth } from '@sentriflow/core/helpers/huawei';

if (!hasIsisDomainAuth(isisNode)) {
  return { passed: false, message: 'Enable IS-IS domain authentication' };
}
```

---

### hasInterfaceIsisAuth

Check if interface has IS-IS authentication configured.

**Signature:**
```typescript
function hasInterfaceIsisAuth(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `isis authentication-mode` is configured.

**Example:**
```typescript
import { hasInterfaceIsisAuth } from '@sentriflow/core/helpers/huawei';

if (!hasInterfaceIsisAuth(interfaceNode)) {
  return { passed: false, message: 'Configure IS-IS authentication on interface' };
}
```

---

### 9. VRRP Helpers

Functions for validating VRRP (Virtual Router Redundancy Protocol) configuration.

---

### hasVrrp

Check if interface has VRRP configured.

**Signature:**
```typescript
function hasVrrp(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `vrrp vrid` is configured.

**Example:**
```typescript
import { hasVrrp, hasVrrpAuthentication } from '@sentriflow/core/helpers/huawei';

if (hasVrrp(interfaceNode) && !hasVrrpAuthentication(interfaceNode)) {
  return { passed: false, message: 'VRRP should have authentication' };
}
```

---

### hasVrrpAuthentication

Check if VRRP has authentication configured.

**Signature:**
```typescript
function hasVrrpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if VRRP authentication-mode is configured.

**Example:**
```typescript
import { hasVrrpAuthentication } from '@sentriflow/core/helpers/huawei';

if (!hasVrrpAuthentication(interfaceNode)) {
  return { passed: false, message: 'Enable VRRP authentication (MD5 recommended)' };
}
```

---

### getVrrpVrid

Get VRRP VRID (Virtual Router ID) from interface.

**Signature:**
```typescript
function getVrrpVrid(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `string | undefined` - VRID or `undefined` if not configured.

**Example:**
```typescript
import { getVrrpVrid } from '@sentriflow/core/helpers/huawei';

const vrid = getVrrpVrid(interfaceNode);
if (vrid) {
  // Check VRRP-specific settings for this VRID
}
```

---

### 10. Interface Security

Functions for validating interface-level security features.

---

### hasIcmpRedirectDisabled

Check if ICMP redirect is disabled on interface.

**Signature:**
```typescript
function hasIcmpRedirectDisabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `undo icmp redirect send` is configured.

**Example:**
```typescript
import { hasIcmpRedirectDisabled } from '@sentriflow/core/helpers/huawei';

if (!hasIcmpRedirectDisabled(interfaceNode)) {
  return { passed: false, message: 'Disable ICMP redirects on external interfaces' };
}
```

---

### hasDirectedBroadcastDisabled

Check if directed broadcast is disabled on interface.

**Signature:**
```typescript
function hasDirectedBroadcastDisabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if directed broadcast is disabled.

**Example:**
```typescript
import { hasDirectedBroadcastDisabled } from '@sentriflow/core/helpers/huawei';

if (!hasDirectedBroadcastDisabled(interfaceNode)) {
  return { passed: false, message: 'Disable directed broadcast to prevent Smurf attacks' };
}
```

---

### hasArpProxyDisabled

Check if ARP proxy is disabled on interface.

**Signature:**
```typescript
function hasArpProxyDisabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if ARP proxy is disabled.

**Example:**
```typescript
import { hasArpProxyDisabled } from '@sentriflow/core/helpers/huawei';

if (!hasArpProxyDisabled(interfaceNode)) {
  return { passed: false, message: 'Disable ARP proxy unless specifically required' };
}
```

---

### hasUrpf

Check if uRPF (Unicast Reverse Path Forwarding) is enabled on interface.

**Signature:**
```typescript
function hasUrpf(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if uRPF is configured (strict or loose).

**Example:**
```typescript
import { hasUrpf } from '@sentriflow/core/helpers/huawei';

if (!hasUrpf(interfaceNode)) {
  return { passed: false, message: 'Enable uRPF on external interfaces' };
}
```

---

### getUrpfMode

Get uRPF mode (strict or loose).

**Signature:**
```typescript
function getUrpfMode(node: ConfigNode): 'strict' | 'loose' | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `'strict' | 'loose' | undefined` - uRPF mode or `undefined` if not configured.

**Example:**
```typescript
import { getUrpfMode } from '@sentriflow/core/helpers/huawei';

const mode = getUrpfMode(interfaceNode);
if (mode === 'loose') {
  // Loose mode needed for asymmetric routing
}
```

---

### hasLldpDisabled

Check if LLDP is disabled on interface.

**Signature:**
```typescript
function hasLldpDisabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `undo lldp enable` is configured.

**Example:**
```typescript
import { hasLldpDisabled } from '@sentriflow/core/helpers/huawei';

// Consider disabling LLDP on external-facing interfaces
if (!hasLldpDisabled(externalInterface)) {
  return { passed: false, message: 'Disable LLDP on external interfaces' };
}
```

---

### 11. NTP Helpers

Functions for validating NTP configuration security.

---

### hasNtpAuthentication

Check if NTP authentication is enabled.

**Signature:**
```typescript
function hasNtpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The NTP configuration node |

**Returns:** `boolean` - `true` if `authentication enable` is configured.

**Example:**
```typescript
import { hasNtpAuthentication } from '@sentriflow/core/helpers/huawei';

if (!hasNtpAuthentication(ntpNode)) {
  return { passed: false, message: 'Enable NTP authentication' };
}
```

---

### hasNtpAuthKey

Check if NTP has authentication key configured.

**Signature:**
```typescript
function hasNtpAuthKey(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The NTP configuration node |

**Returns:** `boolean` - `true` if `authentication-keyid` is configured.

**Example:**
```typescript
import { hasNtpAuthKey, hasNtpAuthentication } from '@sentriflow/core/helpers/huawei';

if (hasNtpAuthentication(ntpNode) && !hasNtpAuthKey(ntpNode)) {
  return { passed: false, message: 'NTP authentication enabled but no key configured' };
}
```

---

### 12. SSH Server Helpers

Functions for validating SSH server security configuration.

---

### hasSshStrongCiphers

Check if SSH server has strong ciphers configured.

**Signature:**
```typescript
function hasSshStrongCiphers(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSH server config node |

**Returns:** `boolean` - `true` if strong ciphers (aes256, aes128) are configured.

**Example:**
```typescript
import { hasSshStrongCiphers } from '@sentriflow/core/helpers/huawei';

if (!hasSshStrongCiphers(sshServerNode)) {
  return { passed: false, message: 'Configure strong SSH ciphers (AES-256 or AES-128)' };
}
```

---

### hasWeakSshAlgorithms

Check for weak SSH algorithms in configuration.

**Signature:**
```typescript
function hasWeakSshAlgorithms(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSH server config node |

**Returns:** `boolean` - `true` if weak algorithms (3des, arcfour, des) are found.

**Example:**
```typescript
import { hasWeakSshAlgorithms } from '@sentriflow/core/helpers/huawei';

if (hasWeakSshAlgorithms(sshServerNode)) {
  return { passed: false, message: 'Remove weak SSH algorithms (3DES, DES, Arcfour)' };
}
```

---

### hasSshStrongHmac

Check if SSH uses strong HMAC algorithms.

**Signature:**
```typescript
function hasSshStrongHmac(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSH server config node |

**Returns:** `boolean` - `true` if strong HMAC (sha2-256, sha2-512) is configured.

**Example:**
```typescript
import { hasSshStrongHmac } from '@sentriflow/core/helpers/huawei';

if (!hasSshStrongHmac(sshServerNode)) {
  return { passed: false, message: 'Configure SHA-256 or SHA-512 for SSH HMAC' };
}
```

---

### hasSshStrongKeyExchange

Check if SSH uses strong key exchange algorithms.

**Signature:**
```typescript
function hasSshStrongKeyExchange(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSH server config node |

**Returns:** `boolean` - `true` if strong key exchange (dh-group14+) is configured.

**Example:**
```typescript
import { hasSshStrongKeyExchange } from '@sentriflow/core/helpers/huawei';

if (!hasSshStrongKeyExchange(sshServerNode)) {
  return { passed: false, message: 'Use DH-group14 or higher for SSH key exchange' };
}
```

---

### 13. CPU-Defend Helpers

Functions for validating control plane protection (CPU-defend) policies.

---

### hasCpuDefendPolicy

Check if node is a CPU-defend policy configuration.

**Signature:**
```typescript
function hasCpuDefendPolicy(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node to check |

**Returns:** `boolean` - `true` if node is a CPU-defend policy.

**Example:**
```typescript
import { hasCpuDefendPolicy } from '@sentriflow/core/helpers/huawei';

if (hasCpuDefendPolicy(node)) {
  // Validate CPU-defend policy settings
}
```

---

### hasCpuDefendAutoDefend

Check if CPU-defend policy has auto-defend enabled.

**Signature:**
```typescript
function hasCpuDefendAutoDefend(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The CPU-defend policy node |

**Returns:** `boolean` - `true` if `auto-defend enable` is configured.

**Example:**
```typescript
import { hasCpuDefendAutoDefend, hasCpuDefendPolicy } from '@sentriflow/core/helpers/huawei';

if (hasCpuDefendPolicy(node) && !hasCpuDefendAutoDefend(node)) {
  return { passed: false, message: 'Enable auto-defend in CPU-defend policy' };
}
```

---

### isCpuDefendPolicyApplied

Check if CPU-defend policy is applied.

**Signature:**
```typescript
function isCpuDefendPolicyApplied(rawText: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rawText | `string` | The raw configuration text |

**Returns:** `boolean` - `true` if `cpu-defend-policy` is applied.

**Example:**
```typescript
import { isCpuDefendPolicyApplied } from '@sentriflow/core/helpers/huawei';

if (!isCpuDefendPolicyApplied(configLine)) {
  // Check if CPU-defend policy needs to be applied
}
```

---

### 14. Service Status Helpers

Functions for checking if insecure services are disabled.

---

### isFtpDisabled

Check if FTP server is disabled.

**Signature:**
```typescript
function isFtpDisabled(rawText: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rawText | `string` | The raw configuration text |

**Returns:** `boolean` - `true` if `undo ftp server enable` is present.

**Example:**
```typescript
import { isFtpDisabled } from '@sentriflow/core/helpers/huawei';

if (!isFtpDisabled(configLine)) {
  return { passed: false, message: 'Disable FTP server - use SFTP instead' };
}
```

---

### isHttpDisabled

Check if HTTP server is disabled.

**Signature:**
```typescript
function isHttpDisabled(rawText: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rawText | `string` | The raw configuration text |

**Returns:** `boolean` - `true` if `undo http server enable` is present.

**Example:**
```typescript
import { isHttpDisabled } from '@sentriflow/core/helpers/huawei';

if (!isHttpDisabled(configLine)) {
  return { passed: false, message: 'Disable HTTP server - use HTTPS instead' };
}
```

---

### isTftpDisabled

Check if TFTP server is disabled.

**Signature:**
```typescript
function isTftpDisabled(rawText: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rawText | `string` | The raw configuration text |

**Returns:** `boolean` - `true` if `undo tftp-server enable` is present.

**Example:**
```typescript
import { isTftpDisabled } from '@sentriflow/core/helpers/huawei';

if (!isTftpDisabled(configLine)) {
  return { passed: false, message: 'Disable TFTP server' };
}
```

---

### isIpSourceRouteDisabled

Check if IP source route is disabled.

**Signature:**
```typescript
function isIpSourceRouteDisabled(rawText: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rawText | `string` | The raw configuration text |

**Returns:** `boolean` - `true` if `undo ip source-route` is present.

**Example:**
```typescript
import { isIpSourceRouteDisabled } from '@sentriflow/core/helpers/huawei';

if (!isIpSourceRouteDisabled(configLine)) {
  return { passed: false, message: 'Disable IP source routing' };
}
```

---

### 15. HWTACACS Helpers

Functions for validating HWTACACS (Huawei TACACS+) configuration.

---

### hasHwtacacsSharedKey

Check if HWTACACS server template has shared-key configured.

**Signature:**
```typescript
function hasHwtacacsSharedKey(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The HWTACACS template node |

**Returns:** `boolean` - `true` if `shared-key cipher` is configured.

**Example:**
```typescript
import { hasHwtacacsSharedKey } from '@sentriflow/core/helpers/huawei';

if (!hasHwtacacsSharedKey(hwtacacsNode)) {
  return { passed: false, message: 'Configure HWTACACS shared-key with cipher' };
}
```

---

### hasHwtacacsSecondary

Check if HWTACACS has secondary server configured for redundancy.

**Signature:**
```typescript
function hasHwtacacsSecondary(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The HWTACACS template node |

**Returns:** `boolean` - `true` if secondary server is configured.

**Example:**
```typescript
import { hasHwtacacsSecondary } from '@sentriflow/core/helpers/huawei';

if (!hasHwtacacsSecondary(hwtacacsNode)) {
  return { passed: false, message: 'Configure secondary HWTACACS server for redundancy' };
}
```

---

### 16. Utility Helpers

General-purpose helper functions for configuration traversal and command parsing.

---

### getCommandValue

Get value for a command that follows the `<command> <value>` pattern.

**Signature:**
```typescript
function getCommandValue(node: ConfigNode, command: string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node |
| command | `string` | The command prefix to search for |

**Returns:** `string | undefined` - The value portion or `undefined`.

**Example:**
```typescript
import { getCommandValue } from '@sentriflow/core/helpers/huawei';

const timeout = getCommandValue(interfaceNode, 'timeout');
// For "timeout 30", returns "30"
```

---

### findStanza

Find a stanza by name in the configuration tree.

**Signature:**
```typescript
function findStanza(node: ConfigNode, stanzaName: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The root node to search from |
| stanzaName | `string` | The stanza name prefix to find |

**Returns:** `ConfigNode | undefined` - The matching node or `undefined`.

**Example:**
```typescript
import { findStanza } from '@sentriflow/core/helpers/huawei';

const bgpNode = findStanza(rootNode, 'bgp');
if (bgpNode) {
  // Process BGP configuration
}
```

---

### findStanzas

Find all stanzas by name in the configuration tree.

**Signature:**
```typescript
function findStanzas(node: ConfigNode, stanzaName: string): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The root node to search from |
| stanzaName | `string` | The stanza name prefix to find |

**Returns:** `ConfigNode[]` - Array of matching nodes.

**Example:**
```typescript
import { findStanzas } from '@sentriflow/core/helpers/huawei';

const interfaces = findStanzas(rootNode, 'interface');
for (const iface of interfaces) {
  // Process each interface
}
```

---

## Re-exported Common Helpers

The following helpers are re-exported from the common helpers module for convenience:

- `hasChildCommand` - Check if node has a child with matching command
- `getChildCommand` - Get a child node by command prefix
- `getChildCommands` - Get all child nodes matching a command prefix

See [Common Helpers](./common.md) for detailed documentation.

---

## See Also

- [Helper Functions Overview](./README.md)
- [Common Helpers](./common.md)
- [Cisco Helpers](./cisco.md) - Similar vendor with different syntax
- [Juniper Helpers](./juniper.md) - Similar hierarchical configuration model
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md)

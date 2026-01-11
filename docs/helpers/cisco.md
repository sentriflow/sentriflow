# Cisco Helper Functions Reference

Cisco helpers provide specialized functions for validating Cisco IOS and IOS-XE router and switch configurations. These helpers understand Cisco-specific syntax, command structures, and security best practices.

## Import Statement

```typescript
import {
  isPhysicalPort,
  isTrunkPort,
  isAccessPort,
  hasOspfAuthentication,
  getBgpNeighbors,
  // ... other helpers
} from '@sentriflow/core/helpers/cisco';
```

Or import everything:

```typescript
import * as cisco from '@sentriflow/core/helpers/cisco';
```

---

## Categories

### 1. Interface Identification

Functions for classifying Cisco interface types.

---

#### isPhysicalPort

Check if interface is a physical port (not Loopback, Vlan, Null, etc.).

**Signature:**
```typescript
function isPhysicalPort(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface identifier from node.id |

**Returns:** `boolean` - `true` if physical port, `false` for virtual interfaces.

**Excluded Types:** Loopback, Null, Vlan, Tunnel, Port-channel, BVI, NVE

**Example:**
```typescript
import { isPhysicalPort } from '@sentriflow/core/helpers/cisco';

isPhysicalPort('GigabitEthernet0/1');     // true
isPhysicalPort('interface Loopback0');     // false
isPhysicalPort('interface Vlan100');       // false
isPhysicalPort('interface Port-channel1'); // false
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "cisco.isPhysicalPort",
  "args": [{ "$ref": "node.id" }]
}
```

---

#### isShutdown

Check if interface is administratively shutdown.

**Signature:**
```typescript
function isShutdown(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if interface has `shutdown` command.

**Example:**
```typescript
import { isShutdown } from '@sentriflow/core/helpers/cisco';

if (isShutdown(interfaceNode)) {
  return { passed: true, message: 'Interface is shutdown - skipping' };
}
```

---

#### isTrunkPort

Check if interface is configured as a trunk.

**Signature:**
```typescript
function isTrunkPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if has `switchport mode trunk`.

**Example:**
```typescript
import { isTrunkPort } from '@sentriflow/core/helpers/cisco';

if (isTrunkPort(interfaceNode)) {
  // Check trunk-specific security settings
}
```

---

#### isAccessPort

Check if interface is configured as an access port.

**Signature:**
```typescript
function isAccessPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if has `switchport mode access`.

**Example:**
```typescript
import { isAccessPort } from '@sentriflow/core/helpers/cisco';

if (isAccessPort(interfaceNode)) {
  // Check access port security settings (portfast, bpduguard, etc.)
}
```

---

#### isLikelyTrunk

Check if interface description suggests it's a trunk/uplink.

**Signature:**
```typescript
function isLikelyTrunk(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if description contains trunk indicators.

**Detection Keywords:** uplink, downlink, isl, trunk, po-member

**Example:**
```typescript
import { isLikelyTrunk } from '@sentriflow/core/helpers/cisco';

// Detects trunks even before mode is explicitly set
if (isLikelyTrunk(interfaceNode)) {
  // Apply trunk security rules
}
```

---

#### isExternalFacing

Check if interface description suggests external-facing (WAN/Internet).

**Signature:**
```typescript
function isExternalFacing(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if description suggests external connectivity.

**Detection Keywords:** wan:, external, internet, isp, dmz, perimeter

**Example:**
```typescript
import { isExternalFacing } from '@sentriflow/core/helpers/cisco';

if (isExternalFacing(interfaceNode)) {
  // Stricter security checks for external interfaces
  // Check for uRPF, ACLs, no ip redirects, etc.
}
```

---

#### isEndpointPort

Check if interface description suggests user endpoint port.

**Signature:**
```typescript
function isEndpointPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if connected to user devices.

**Detection Keywords:** endpoint:, user:, workstation, desktop, desk

**Example:**
```typescript
import { isEndpointPort } from '@sentriflow/core/helpers/cisco';

if (isEndpointPort(interfaceNode)) {
  // Check for 802.1X, port security, DHCP snooping trust
}
```

---

#### isPhoneOrAP

Check if interface description suggests phone or access point.

**Signature:**
```typescript
function isPhoneOrAP(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if connected to phone or AP.

**Detection Keywords:** phone, voice, cisco-ap, aruba-ap, ap-, -ap, or has `switchport voice vlan`

**Example:**
```typescript
import { isPhoneOrAP } from '@sentriflow/core/helpers/cisco';

if (isPhoneOrAP(interfaceNode)) {
  // Voice VLAN configurations apply
}
```

---

#### isTrunkToNonCisco

Check if trunk is connected to a non-Cisco device (requires nonegotiate).

**Signature:**
```typescript
function isTrunkToNonCisco(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if trunk connects to non-Cisco device.

**Detection Keywords:** server:, storage:, esx, vmware, hyperv, linux, appliance, firewall, loadbalancer, lb:, nas:, san:

**Example:**
```typescript
import { isTrunkToNonCisco, isTrunkPort } from '@sentriflow/core/helpers/cisco';

if (isTrunkPort(node) && isTrunkToNonCisco(node)) {
  // Should have "switchport nonegotiate" since other end doesn't speak DTP
}
```

---

#### isLoopbackInterface

Check if interface is a loopback.

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
import { isLoopbackInterface } from '@sentriflow/core/helpers/cisco';

isLoopbackInterface('Loopback0');  // true
isLoopbackInterface('GigabitEthernet0/1');  // false
```

---

#### isTunnelInterface

Check if interface is a tunnel.

**Signature:**
```typescript
function isTunnelInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if tunnel interface.

**Example:**
```typescript
import { isTunnelInterface } from '@sentriflow/core/helpers/cisco';

isTunnelInterface('Tunnel100');  // true
```

---

#### isVlanInterface

Check if interface is a VLAN SVI.

**Signature:**
```typescript
function isVlanInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if VLAN SVI.

**Example:**
```typescript
import { isVlanInterface } from '@sentriflow/core/helpers/cisco';

isVlanInterface('interface Vlan100');  // true
isVlanInterface('interface GigabitEthernet0/1');  // false
```

---

#### isWanInterface

Check if interface is WAN/Internet-facing based on description.

**Signature:**
```typescript
function isWanInterface(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if WAN/Internet-facing.

**Detection Keywords:** wan, internet, isp, external, outside, border, edge

**Example:**
```typescript
import { isWanInterface } from '@sentriflow/core/helpers/cisco';

if (isWanInterface(interfaceNode)) {
  // Stricter security for WAN interfaces
}
```

---

### 2. Management Plane Helpers

Functions for validating management access security.

---

#### isAaaNewModel

Check if AAA new-model is configured.

**Signature:**
```typescript
function isAaaNewModel(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The global config node to check |

**Returns:** `boolean` - `true` if node is `aaa new-model`.

**Example:**
```typescript
import { isAaaNewModel } from '@sentriflow/core/helpers/cisco';

// Use with AST to find if AAA is enabled
const hasAaa = ast.some(isAaaNewModel);
```

---

#### hasStrongPasswordType

Check if password uses strong encryption (SHA-256, scrypt, or secret).

**Signature:**
```typescript
function hasStrongPasswordType(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The username or password node |

**Returns:** `boolean` - `true` if using strong encryption.

**Strong Types:** algorithm-type sha256, algorithm-type scrypt, secret (type 5+)

**Example:**
```typescript
import { hasStrongPasswordType } from '@sentriflow/core/helpers/cisco';

// Check username password strength
if (!hasStrongPasswordType(usernameNode)) {
  // Flag weak password encryption
}
```

---

#### hasWeakUsernamePassword

Check if username uses weak password type (Type 7 or plaintext).

**Signature:**
```typescript
function hasWeakUsernamePassword(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The username node |

**Returns:** `boolean` - `true` if using weak password encryption.

**Example:**
```typescript
import { hasWeakUsernamePassword } from '@sentriflow/core/helpers/cisco';

if (hasWeakUsernamePassword(usernameNode)) {
  return { passed: false, message: 'Username uses weak password encryption' };
}
```

---

#### getSshVersion

Get SSH version from configuration.

**Signature:**
```typescript
function getSshVersion(node: ConfigNode): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSH version config node |

**Returns:** `number | null` - 1 or 2, or `null` if not found.

**Example:**
```typescript
import { getSshVersion } from '@sentriflow/core/helpers/cisco';

const version = getSshVersion(sshNode);
if (version === 1) {
  return { passed: false, message: 'SSH version 1 is insecure' };
}
```

---

#### isDefaultSnmpCommunity

Check if SNMP community is a well-known default.

**Signature:**
```typescript
function isDefaultSnmpCommunity(community: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| community | `string` | The SNMP community string |

**Returns:** `boolean` - `true` if default community name.

**Default Communities:** public, private, community, snmp, admin, cisco, secret, test, default

**Example:**
```typescript
import { isDefaultSnmpCommunity } from '@sentriflow/core/helpers/cisco';

const community = snmpNode.params[2];
if (isDefaultSnmpCommunity(community)) {
  return { passed: false, message: 'Using default SNMP community' };
}
```

---

#### isSnmpV3User

Check if node is an SNMP v3 user configuration.

**Signature:**
```typescript
function isSnmpV3User(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node |

**Returns:** `boolean` - `true` if `snmp-server user` configuration.

**Example:**
```typescript
import { isSnmpV3User } from '@sentriflow/core/helpers/cisco';

if (isSnmpV3User(node)) {
  // Validate SNMPv3 security settings
}
```

---

#### hasSnmpV3AuthPriv

Check if SNMP v3 uses authentication and privacy.

**Signature:**
```typescript
function hasSnmpV3AuthPriv(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SNMP user node |

**Returns:** `boolean` - `true` if auth-priv is configured.

**Example:**
```typescript
import { hasSnmpV3AuthPriv, isSnmpV3User } from '@sentriflow/core/helpers/cisco';

if (isSnmpV3User(node) && !hasSnmpV3AuthPriv(node)) {
  return { passed: false, message: 'SNMPv3 should use auth-priv' };
}
```

---

#### getVtyLineRange

Get VTY line range from node.

**Signature:**
```typescript
function getVtyLineRange(node: ConfigNode): { start: number; end: number } | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VTY line node |

**Returns:** `{ start: number; end: number } | null` - Line range or `null`.

**Example:**
```typescript
import { getVtyLineRange } from '@sentriflow/core/helpers/cisco';

// For "line vty 0 15"
const range = getVtyLineRange(vtyNode);
// Returns { start: 0, end: 15 }
```

---

#### hasVtyAccessClass

Check if VTY has access-class configured.

**Signature:**
```typescript
function hasVtyAccessClass(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VTY line node |

**Returns:** `boolean` - `true` if access-class is configured.

**Example:**
```typescript
import { hasVtyAccessClass } from '@sentriflow/core/helpers/cisco';

if (!hasVtyAccessClass(vtyNode)) {
  return { passed: false, message: 'VTY lines should have access-class' };
}
```

---

#### hasNtpAuthentication

Check if NTP authentication is enabled.

**Signature:**
```typescript
function hasNtpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node |

**Returns:** `boolean` - `true` if NTP authentication configured.

**Example:**
```typescript
import { hasNtpAuthentication } from '@sentriflow/core/helpers/cisco';

// Check for NTP security
const hasNtpAuth = ast.some(hasNtpAuthentication);
```

---

### 3. Control Plane / Routing Helpers

Functions for validating routing protocol security.

---

#### hasOspfAuthentication

Check if OSPF authentication is configured on interface.

**Signature:**
```typescript
function hasOspfAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if OSPF authentication configured.

**Checks for:** `ip ospf authentication` or `ip ospf message-digest-key`

**Example:**
```typescript
import { hasOspfAuthentication } from '@sentriflow/core/helpers/cisco';

if (!hasOspfAuthentication(interfaceNode)) {
  return { passed: false, message: 'OSPF authentication not configured' };
}
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "cisco.hasOspfAuthentication",
  "args": [{ "$ref": "node" }],
  "negate": true
}
```

---

#### hasEigrpAuthentication

Check if EIGRP authentication is configured on interface.

**Signature:**
```typescript
function hasEigrpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if EIGRP authentication configured.

**Checks for:** `ip authentication mode eigrp` AND `ip authentication key-chain eigrp`

**Example:**
```typescript
import { hasEigrpAuthentication } from '@sentriflow/core/helpers/cisco';

if (!hasEigrpAuthentication(interfaceNode)) {
  return { passed: false, message: 'EIGRP authentication not configured' };
}
```

---

#### getBgpNeighbors

Get all BGP neighbors from router bgp section.

**Signature:**
```typescript
function getBgpNeighbors(node: ConfigNode): Map<string, ConfigNode[]>
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |

**Returns:** `Map<string, ConfigNode[]>` - Map of neighbor IP to all their config commands.

**Example:**
```typescript
import { getBgpNeighbors, hasBgpNeighborPassword } from '@sentriflow/core/helpers/cisco';

const neighbors = getBgpNeighbors(routerBgpNode);
for (const [ip, commands] of neighbors) {
  if (!hasBgpNeighborPassword(commands)) {
    // Flag neighbor without password
  }
}
```

---

#### hasBgpNeighborPassword

Check if BGP neighbor has password configured.

**Signature:**
```typescript
function hasBgpNeighborPassword(neighborCommands: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| neighborCommands | `ConfigNode[]` | Array of neighbor config commands |

**Returns:** `boolean` - `true` if password is configured.

**Example:**
```typescript
import { getBgpNeighbors, hasBgpNeighborPassword } from '@sentriflow/core/helpers/cisco';

const neighbors = getBgpNeighbors(routerBgpNode);
for (const [ip, commands] of neighbors) {
  if (!hasBgpNeighborPassword(commands)) {
    return { passed: false, message: `BGP neighbor ${ip} has no password` };
  }
}
```

---

#### hasBgpTtlSecurity

Check if BGP neighbor has TTL security (GTSM) configured.

**Signature:**
```typescript
function hasBgpTtlSecurity(neighborCommands: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| neighborCommands | `ConfigNode[]` | Array of neighbor config commands |

**Returns:** `boolean` - `true` if TTL security is configured.

**Example:**
```typescript
import { getBgpNeighbors, hasBgpTtlSecurity } from '@sentriflow/core/helpers/cisco';

const neighbors = getBgpNeighbors(routerBgpNode);
for (const [ip, commands] of neighbors) {
  if (!hasBgpTtlSecurity(commands)) {
    // Consider enabling GTSM for eBGP
  }
}
```

---

#### hasBgpMaxPrefix

Check if BGP neighbor has maximum-prefix configured.

**Signature:**
```typescript
function hasBgpMaxPrefix(neighborCommands: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| neighborCommands | `ConfigNode[]` | Array of neighbor config commands |

**Returns:** `boolean` - `true` if maximum-prefix is configured.

**Example:**
```typescript
import { getBgpNeighbors, hasBgpMaxPrefix } from '@sentriflow/core/helpers/cisco';

const neighbors = getBgpNeighbors(routerBgpNode);
for (const [ip, commands] of neighbors) {
  if (!hasBgpMaxPrefix(commands)) {
    // Recommend setting maximum-prefix
  }
}
```

---

#### hasBgpLogNeighborChanges

Check if BGP has log-neighbor-changes enabled.

**Signature:**
```typescript
function hasBgpLogNeighborChanges(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router bgp section node |

**Returns:** `boolean` - `true` if log-neighbor-changes is enabled.

**Example:**
```typescript
import { hasBgpLogNeighborChanges } from '@sentriflow/core/helpers/cisco';

if (!hasBgpLogNeighborChanges(routerBgpNode)) {
  return { passed: false, message: 'Enable bgp log-neighbor-changes' };
}
```

---

#### hasHsrpMd5Auth

Check if HSRP has MD5 authentication.

**Signature:**
```typescript
function hasHsrpMd5Auth(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if HSRP MD5 authentication configured.

**Example:**
```typescript
import { hasHsrpMd5Auth } from '@sentriflow/core/helpers/cisco';

if (!hasHsrpMd5Auth(interfaceNode)) {
  return { passed: false, message: 'HSRP should use MD5 authentication' };
}
```

---

#### hasVrrpAuthentication

Check if VRRP has authentication.

**Signature:**
```typescript
function hasVrrpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if VRRP authentication configured.

**Example:**
```typescript
import { hasVrrpAuthentication } from '@sentriflow/core/helpers/cisco';

if (!hasVrrpAuthentication(interfaceNode)) {
  return { passed: false, message: 'VRRP should have authentication' };
}
```

---

### 4. Data Plane Helpers

Functions for validating forwarding and interface security.

---

#### hasUrpf

Check if interface has uRPF (unicast RPF) enabled.

**Signature:**
```typescript
function hasUrpf(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if uRPF is configured.

**Example:**
```typescript
import { hasUrpf, isExternalFacing } from '@sentriflow/core/helpers/cisco';

if (isExternalFacing(interfaceNode) && !hasUrpf(interfaceNode)) {
  return { passed: false, message: 'External interface should have uRPF' };
}
```

---

#### getUrpfMode

Get uRPF mode (strict or loose).

**Signature:**
```typescript
function getUrpfMode(node: ConfigNode): 'strict' | 'loose' | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `'strict' | 'loose' | null` - uRPF mode or `null` if not configured.

**Details:**
- `rx` = strict mode
- `any` = loose mode

**Example:**
```typescript
import { getUrpfMode } from '@sentriflow/core/helpers/cisco';

const mode = getUrpfMode(interfaceNode);
if (mode === 'loose') {
  // Loose mode is less secure but needed for asymmetric routing
}
```

---

#### hasNoIpRedirects

Check if IP redirects are disabled.

**Signature:**
```typescript
function hasNoIpRedirects(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `no ip redirects` is configured.

**Example:**
```typescript
import { hasNoIpRedirects } from '@sentriflow/core/helpers/cisco';

if (!hasNoIpRedirects(interfaceNode)) {
  return { passed: false, message: 'Disable ip redirects on this interface' };
}
```

---

#### hasNoIpUnreachables

Check if IP unreachables are disabled.

**Signature:**
```typescript
function hasNoIpUnreachables(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `no ip unreachables` is configured.

**Example:**
```typescript
import { hasNoIpUnreachables } from '@sentriflow/core/helpers/cisco';

if (!hasNoIpUnreachables(interfaceNode)) {
  // Consider disabling to prevent network reconnaissance
}
```

---

#### hasNoProxyArp

Check if IP proxy-arp is disabled.

**Signature:**
```typescript
function hasNoProxyArp(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `no ip proxy-arp` is configured.

**Example:**
```typescript
import { hasNoProxyArp } from '@sentriflow/core/helpers/cisco';

if (!hasNoProxyArp(interfaceNode)) {
  return { passed: false, message: 'Disable proxy-arp on this interface' };
}
```

---

#### hasNoDirectedBroadcast

Check if IP directed-broadcast is disabled.

**Signature:**
```typescript
function hasNoDirectedBroadcast(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if `no ip directed-broadcast` is configured.

**Example:**
```typescript
import { hasNoDirectedBroadcast } from '@sentriflow/core/helpers/cisco';

if (!hasNoDirectedBroadcast(interfaceNode)) {
  // Directed broadcasts can be used for Smurf attacks
}
```

---

### 5. Service Hardening Helpers

Functions for validating global service security.

---

#### hasPasswordEncryption

Check if service password-encryption is enabled.

**Signature:**
```typescript
function hasPasswordEncryption(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The global config node |

**Returns:** `boolean` - `true` if node is `service password-encryption`.

**Example:**
```typescript
import { hasPasswordEncryption } from '@sentriflow/core/helpers/cisco';

const hasEncryption = ast.some(hasPasswordEncryption);
if (!hasEncryption) {
  return { passed: false, message: 'Enable service password-encryption' };
}
```

---

#### hasTcpKeepalives

Check if TCP keepalives are enabled.

**Signature:**
```typescript
function hasTcpKeepalives(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The global config node |

**Returns:** `boolean` - `true` if `service tcp-keepalives-in` or `service tcp-keepalives-out`.

**Example:**
```typescript
import { hasTcpKeepalives } from '@sentriflow/core/helpers/cisco';

const hasBothKeepalives = ast.filter(hasTcpKeepalives).length >= 2;
```

---

#### isDangerousService

Check if service should be disabled for security.

**Signature:**
```typescript
function isDangerousService(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The global config node |

**Returns:** `boolean` - `true` if service should be disabled.

**Dangerous Services:**
- service tcp-small-servers
- service udp-small-servers
- ip finger / service finger
- ip bootp server
- service config
- ip http server
- service pad
- boot network
- service call-home

**Example:**
```typescript
import { isDangerousService } from '@sentriflow/core/helpers/cisco';

if (isDangerousService(node)) {
  return { passed: false, message: 'Disable this dangerous service' };
}
```

---

#### isSmartInstallEnabled

Check if Smart Install (vstack) is enabled.

**Signature:**
```typescript
function isSmartInstallEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The global config node |

**Returns:** `boolean` - `true` if vstack is enabled.

**Security Note:** Smart Install has known vulnerabilities (CVE-2018-0171) and should be disabled.

**Example:**
```typescript
import { isSmartInstallEnabled } from '@sentriflow/core/helpers/cisco';

if (isSmartInstallEnabled(node)) {
  return {
    passed: false,
    message: 'Disable Smart Install (vstack) - known security vulnerability',
    remediation: 'Configure "no vstack"'
  };
}
```

---

## See Also

- [Helper Functions Overview](./README.md)
- [Common Helpers](./common.md)
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md)

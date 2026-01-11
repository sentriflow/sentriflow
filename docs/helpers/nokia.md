# Nokia SR OS Helper Functions Reference

Nokia SR OS helpers provide specialized functions for validating Nokia Service Router Operating System configurations. These helpers understand the Nokia SR OS hierarchical configuration syntax, admin-state management, and security best practices for service provider core routers, aggregation routers, and MPLS/VPN platforms.

Nokia SR OS (Service Router Operating System) is the network operating system that powers Nokia's 7750 SR, 7450 ESS, 7705 SAR, and 7250 IXR series routers. It uses a hierarchical configuration model with admin-state controls and is widely deployed in service provider networks for MPLS, L3VPN, L2VPN, and metro Ethernet services.

## Import Statement

```typescript
import {
  findStanza,
  findStanzas,
  isAdminStateEnabled,
  hasBgpAuthentication,
  hasCpmFilter,
  // ... other helpers
} from '@sentriflow/core/helpers/nokia';
```

Or import everything:

```typescript
import * as nokia from '@sentriflow/core/helpers/nokia';
```

---

## Categories

### 1. Administrative State Helpers

Functions for checking Nokia SR OS admin-state configuration. Nokia uses `admin-state enable/disable` for controlling component activation.

---

#### isAdminStateEnabled

Check if admin-state is enabled (`admin-state enable` or `admin-state up`). Nokia SR OS uses admin-state for enabling/disabling most components.

**Signature:**
```typescript
function isAdminStateEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The configuration node to check |

**Returns:** `boolean` - `true` if admin-state is enable or up.

**Example:**
```typescript
import { isAdminStateEnabled } from '@sentriflow/core/helpers/nokia';

if (!isAdminStateEnabled(interfaceNode)) {
  return { passed: true, message: 'Interface is disabled - skipping' };
}
```

---

#### isAdminStateDisabled

Check if admin-state is disabled (`admin-state disable`).

**Signature:**
```typescript
function isAdminStateDisabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The configuration node to check |

**Returns:** `boolean` - `true` if admin-state is explicitly disabled.

---

#### isShutdown

Check if component has shutdown command configured.

**Signature:**
```typescript
function isShutdown(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The configuration node to check |

**Returns:** `boolean` - `true` if shutdown command is present.

---

#### isEnabled

Check if interface/component is enabled (has admin-state enable AND no shutdown).

**Signature:**
```typescript
function isEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The configuration node to check |

**Returns:** `boolean` - `true` if component is operationally enabled.

**Example:**
```typescript
import { isEnabled } from '@sentriflow/core/helpers/nokia';

if (isEnabled(portNode)) {
  // Port is active - apply security checks
}
```

---

### 2. Port/Interface Identification

Functions for classifying Nokia SR OS port and interface types.

---

#### isPhysicalPort

Check if a port is a physical port (not LAG, loopback, or system). Nokia port format: slot/mda/port (e.g., 1/1/1, 1/2/3).

**Signature:**
```typescript
function isPhysicalPort(portName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| portName | `string` | The port name to check |

**Returns:** `boolean` - `true` if physical port.

**Example:**
```typescript
import { isPhysicalPort } from '@sentriflow/core/helpers/nokia';

isPhysicalPort('1/1/1');     // true
isPhysicalPort('1/2/3');     // true
isPhysicalPort('lag-1');     // false
isPhysicalPort('system');    // false
```

---

#### isLagPort

Check if a port is a LAG (Link Aggregation Group). Nokia LAG format: lag-N or lag N.

**Signature:**
```typescript
function isLagPort(portName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| portName | `string` | The port name to check |

**Returns:** `boolean` - `true` if LAG port.

**Example:**
```typescript
import { isLagPort } from '@sentriflow/core/helpers/nokia';

isLagPort('lag-1');    // true
isLagPort('lag 10');   // true
isLagPort('1/1/1');    // false
```

---

#### isSystemInterface

Check if interface is a system interface (loopback, system).

**Signature:**
```typescript
function isSystemInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name to check |

**Returns:** `boolean` - `true` if system or loopback interface.

**Example:**
```typescript
import { isSystemInterface } from '@sentriflow/core/helpers/nokia';

isSystemInterface('system');     // true
isSystemInterface('"system"');   // true
isSystemInterface('loopback');   // true
isSystemInterface('to-PE2');     // false
```

---

### 3. Port Configuration

Functions for checking port configuration settings.

---

#### getPortMode

Get port mode (network or access) from port configuration.

**Signature:**
```typescript
function getPortMode(node: ConfigNode): 'network' | 'access' | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The port node to check |

**Returns:** `'network' | 'access' | undefined` - The port mode if configured.

**Example:**
```typescript
import { getPortMode } from '@sentriflow/core/helpers/nokia';

const mode = getPortMode(portNode);
if (mode === 'network') {
  // Apply network port security checks
}
```

---

#### isNetworkPort

Check if port is in network mode.

**Signature:**
```typescript
function isNetworkPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The port node to check |

**Returns:** `boolean` - `true` if port mode is network.

---

#### isAccessPort

Check if port is in access mode.

**Signature:**
```typescript
function isAccessPort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The port node to check |

**Returns:** `boolean` - `true` if port mode is access.

---

#### hasDescription

Check if port has description configured.

**Signature:**
```typescript
function hasDescription(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The port or interface node to check |

**Returns:** `boolean` - `true` if description is configured.

---

#### getDescription

Get port/interface description text.

**Signature:**
```typescript
function getDescription(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The port or interface node |

**Returns:** `string | undefined` - The description text or undefined.

**Example:**
```typescript
import { getDescription } from '@sentriflow/core/helpers/nokia';

const desc = getDescription(portNode);
// Returns: "Uplink to Core-PE1"
```

---

### 4. Interface Configuration

Functions for checking interface IP and assignment configuration.

---

#### hasIpAddress

Check if interface has IP address configured.

**Signature:**
```typescript
function hasIpAddress(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if address is configured.

---

#### getIpAddress

Get interface IP address.

**Signature:**
```typescript
function getIpAddress(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `string | undefined` - The IP address with optional prefix (e.g., "10.0.0.1/30").

**Example:**
```typescript
import { getIpAddress } from '@sentriflow/core/helpers/nokia';

const ip = getIpAddress(interfaceNode);
// Returns: "10.0.0.1/30"
```

---

#### hasPortAssignment

Check if interface has port assigned.

**Signature:**
```typescript
function hasPortAssignment(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if port assignment exists.

---

#### getPortAssignment

Get port assignment from interface.

**Signature:**
```typescript
function getPortAssignment(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `string | undefined` - The port identifier (e.g., "1/1/1").

---

#### getInterfaceName

Get interface name from quoted or unquoted format. Nokia uses: `interface "name"` or `interface name`.

**Signature:**
```typescript
function getInterfaceName(node: ConfigNode): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `string` - The interface name without quotes.

**Example:**
```typescript
import { getInterfaceName } from '@sentriflow/core/helpers/nokia';

// For node.id = 'interface "to-PE2"'
getInterfaceName(interfaceNode);  // Returns: "to-PE2"
```

---

### 5. System Configuration

Functions for extracting system-level configuration.

---

#### getSystemName

Get system name from system block.

**Signature:**
```typescript
function getSystemName(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The system node |

**Returns:** `string | undefined` - The system name.

**Example:**
```typescript
import { getSystemName, findStanza } from '@sentriflow/core/helpers/nokia';

const system = findStanza(rootNode, 'system');
const name = getSystemName(system);
// Returns: "PE-Router-01"
```

---

#### getRouterName

Get router name from router block. Nokia uses: `router "Base"` or `router vprn-name`.

**Signature:**
```typescript
function getRouterName(node: ConfigNode): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The router node |

**Returns:** `string` - The router name (defaults to "Base" if not specified).

---

### 6. Node Navigation

Functions for traversing Nokia SR OS hierarchical configuration.

---

#### findStanza

Find a stanza by name in the configuration tree.

**Signature:**
```typescript
function findStanza(node: ConfigNode, stanzaName: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| stanzaName | `string` | The stanza name to find (case-insensitive prefix match) |

**Returns:** `ConfigNode | undefined` - The matching node.

**Example:**
```typescript
import { findStanza } from '@sentriflow/core/helpers/nokia';

// Find system stanza
const system = findStanza(rootNode, 'system');

// Find router stanza
const router = findStanza(rootNode, 'router');

// Find BGP within router
const bgp = findStanza(router, 'bgp');
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "nokia.findStanza",
  "args": [{ "$ref": "node" }, "system"]
}
```

---

#### findStanzas

Find all stanzas by name in the configuration tree.

**Signature:**
```typescript
function findStanzas(node: ConfigNode, stanzaName: string): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| stanzaName | `string` | The stanza name to find (case-insensitive prefix match) |

**Returns:** `ConfigNode[]` - Array of matching nodes.

**Example:**
```typescript
import { findStanzas } from '@sentriflow/core/helpers/nokia';

// Find all interface stanzas
const interfaces = findStanzas(routerNode, 'interface');

// Find all BGP groups
const groups = findStanzas(bgpNode, 'group');
```

---

### 7. Service Configuration

Functions for Nokia MPLS/VPN service configuration.

---

#### hasSap

Check if SAP (Service Access Point) is configured.

**Signature:**
```typescript
function hasSap(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The service interface node |

**Returns:** `boolean` - `true` if SAP is configured.

---

#### getSapId

Get SAP identifier. SAP format: `sap port:vlan` (e.g., `sap 1/1/1:100`).

**Signature:**
```typescript
function getSapId(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The service interface node |

**Returns:** `string | undefined` - The SAP identifier.

**Example:**
```typescript
import { getSapId } from '@sentriflow/core/helpers/nokia';

const sap = getSapId(serviceInterfaceNode);
// Returns: "1/1/1:100"
```

---

#### getServiceType

Get service type from service block.

**Signature:**
```typescript
function getServiceType(node: ConfigNode): 'vpls' | 'vprn' | 'epipe' | 'ies' | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The service node |

**Returns:** `'vpls' | 'vprn' | 'epipe' | 'ies' | undefined` - The service type.

**Service Types:**
- `vpls` - Virtual Private LAN Service (L2VPN multipoint)
- `vprn` - Virtual Private Routed Network (L3VPN)
- `epipe` - Ethernet Pipe (L2VPN point-to-point)
- `ies` - Internet Enhanced Service

---

#### getServiceId

Get service ID from service block.

**Signature:**
```typescript
function getServiceId(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The service node |

**Returns:** `string | undefined` - The numeric service ID.

---

#### hasCustomer

Check if customer is assigned to service.

**Signature:**
```typescript
function hasCustomer(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The service node |

**Returns:** `boolean` - `true` if customer is assigned.

---

#### getCustomerId

Get customer ID from service.

**Signature:**
```typescript
function getCustomerId(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The service node |

**Returns:** `string | undefined` - The numeric customer ID.

---

### 8. Management Plane Security

Functions for validating management access security on Nokia SR OS.

---

#### isSnmpEnabled

Check if SNMP is configured and enabled (snmp block with admin-state enable).

**Signature:**
```typescript
function isSnmpEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The snmp node |

**Returns:** `boolean` - `true` if SNMP is enabled.

---

#### hasNtpServer

Check if NTP server is configured.

**Signature:**
```typescript
function hasNtpServer(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The system or ntp node |

**Returns:** `boolean` - `true` if NTP server is configured.

---

#### isSshEnabled

Check if SSH is enabled in security settings.

**Signature:**
```typescript
function isSshEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The security or management-interface node |

**Returns:** `boolean` - `true` if SSH is enabled.

---

#### isTelnetEnabled

Check if Telnet is enabled (security concern - insecure protocol).

**Signature:**
```typescript
function isTelnetEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The security or management-interface node |

**Returns:** `boolean` - `true` if Telnet is enabled.

**Example:**
```typescript
import { isTelnetEnabled } from '@sentriflow/core/helpers/nokia';

if (isTelnetEnabled(securityNode)) {
  return { passed: false, message: 'Telnet should be disabled' };
}
```

---

#### hasAuthentication

Check if authentication is configured (authentication, auth-key, or password).

**Signature:**
```typescript
function hasAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The node to check |

**Returns:** `boolean` - `true` if authentication is configured.

---

#### hasTacacsConfig

Check if TACACS+ is configured for AAA.

**Signature:**
```typescript
function hasTacacsConfig(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The aaa or system node |

**Returns:** `boolean` - `true` if tacplus is configured.

---

#### hasRadiusConfig

Check if RADIUS is configured for AAA.

**Signature:**
```typescript
function hasRadiusConfig(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The aaa or system node |

**Returns:** `boolean` - `true` if radius is configured.

---

#### hasSshV2

Check if SSH version 2 is configured.

**Signature:**
```typescript
function hasSshV2(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ssh or security node |

**Returns:** `boolean` - `true` if SSH v2 is configured.

---

#### hasSshV1

Check if SSHv1 is explicitly enabled (security concern - deprecated protocol).

**Signature:**
```typescript
function hasSshV1(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ssh or security node |

**Returns:** `boolean` - `true` if SSH v1 is enabled.

**Example:**
```typescript
import { hasSshV1 } from '@sentriflow/core/helpers/nokia';

if (hasSshV1(sshNode)) {
  return { passed: false, message: 'SSH v1 should be disabled' };
}
```

---

#### hasWeakSshCipher

Check if weak SSH ciphers are configured.

**Signature:**
```typescript
function hasWeakSshCipher(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ssh node |

**Returns:** `boolean` - `true` if weak ciphers are configured.

**Weak Ciphers:** 3des-cbc, blowfish-cbc, cast128-cbc, arcfour, rijndael-cbc

---

#### hasSnmpV3Privacy

Check if SNMPv3 with privacy is configured.

**Signature:**
```typescript
function hasSnmpV3Privacy(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The snmp node |

**Returns:** `boolean` - `true` if SNMPv3 with privacy is configured.

---

#### hasDefaultSnmpCommunity

Check if default SNMP community strings are used (public/private).

**Signature:**
```typescript
function hasDefaultSnmpCommunity(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The snmp node |

**Returns:** `boolean` - `true` if default community strings are used.

**Example:**
```typescript
import { hasDefaultSnmpCommunity } from '@sentriflow/core/helpers/nokia';

if (hasDefaultSnmpCommunity(snmpNode)) {
  return { passed: false, message: 'Default SNMP community strings should be changed' };
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
| node | `ConfigNode` | The ntp node |

**Returns:** `boolean` - `true` if NTP authentication is configured.

---

#### hasManagementAccessFilter

Check if management access filter (MAF) is configured.

**Signature:**
```typescript
function hasManagementAccessFilter(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The system or security node |

**Returns:** `boolean` - `true` if MAF is configured.

---

#### hasMafDefaultDeny

Check if MAF has default-action deny.

**Signature:**
```typescript
function hasMafDefaultDeny(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The management-access-filter node |

**Returns:** `boolean` - `true` if default-action is deny.

**Example:**
```typescript
import { hasManagementAccessFilter, hasMafDefaultDeny } from '@sentriflow/core/helpers/nokia';

if (hasManagementAccessFilter(systemNode)) {
  if (!hasMafDefaultDeny(mafNode)) {
    return { passed: false, message: 'MAF default-action should be deny' };
  }
}
```

---

### 9. Control Plane Security / Routing

Functions for validating routing protocol authentication.

---

#### hasOspfAuthentication

Check if OSPF authentication is configured (auth-keychain, authentication-key, or message-digest-key).

**Signature:**
```typescript
function hasOspfAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The OSPF interface or area node |

**Returns:** `boolean` - `true` if authentication is configured.

**Example:**
```typescript
import { hasOspfAuthentication } from '@sentriflow/core/helpers/nokia';

if (!hasOspfAuthentication(ospfInterfaceNode)) {
  return { passed: false, message: 'OSPF authentication should be configured' };
}
```

---

#### hasIsisAuthentication

Check if IS-IS authentication is configured.

**Signature:**
```typescript
function hasIsisAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The IS-IS interface or level node |

**Returns:** `boolean` - `true` if authentication is configured.

---

#### hasLdpAuthentication

Check if LDP authentication is configured.

**Signature:**
```typescript
function hasLdpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The LDP interface or peer node |

**Returns:** `boolean` - `true` if authentication is configured.

---

#### hasRsvpAuthentication

Check if RSVP authentication is configured.

**Signature:**
```typescript
function hasRsvpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The RSVP interface node |

**Returns:** `boolean` - `true` if authentication is configured.

---

### 10. BGP Security

Functions for validating BGP security configuration.

---

#### hasBgpRouterId

Check if BGP has router-id configured.

**Signature:**
```typescript
function hasBgpRouterId(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP node |

**Returns:** `boolean` - `true` if router-id is configured.

---

#### getBgpRouterId

Get BGP router-id.

**Signature:**
```typescript
function getBgpRouterId(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP node |

**Returns:** `string | undefined` - The router-id IP address.

---

#### hasPeerDescription

Check if BGP peer has description configured.

**Signature:**
```typescript
function hasPeerDescription(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP neighbor node |

**Returns:** `boolean` - `true` if description is configured.

---

#### hasBgpAuthentication

Check if BGP authentication is configured (auth-keychain, authentication-key, or password).

**Signature:**
```typescript
function hasBgpAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP neighbor or group node |

**Returns:** `boolean` - `true` if authentication is configured.

**Example:**
```typescript
import { hasBgpAuthentication, findStanzas } from '@sentriflow/core/helpers/nokia';

const neighbors = findStanzas(bgpGroupNode, 'neighbor');
for (const neighbor of neighbors) {
  if (!hasBgpAuthentication(neighbor)) {
    // Flag neighbor without authentication
  }
}
```

---

#### hasBgpTtlSecurity

Check if BGP TTL security (GTSM) is configured.

**Signature:**
```typescript
function hasBgpTtlSecurity(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP neighbor or group node |

**Returns:** `boolean` - `true` if ttl-security is configured.

---

#### hasBgpPrefixLimit

Check if BGP prefix-limit is configured.

**Signature:**
```typescript
function hasBgpPrefixLimit(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP neighbor or group node |

**Returns:** `boolean` - `true` if prefix-limit is configured.

---

#### hasBgpGracefulRestart

Check if BGP graceful restart is configured.

**Signature:**
```typescript
function hasBgpGracefulRestart(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP node |

**Returns:** `boolean` - `true` if graceful-restart is configured.

---

#### hasBgpPolicies

Check if BGP import/export policies are configured.

**Signature:**
```typescript
function hasBgpPolicies(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP neighbor or group node |

**Returns:** `boolean` - `true` if import or export policies are configured.

---

#### isBgpExternalGroup

Check if BGP group is external type (eBGP).

**Signature:**
```typescript
function isBgpExternalGroup(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP group node |

**Returns:** `boolean` - `true` if group type is external.

---

#### getBgpNeighborIp

Get BGP neighbor IP address from neighbor node.

**Signature:**
```typescript
function getBgpNeighborIp(node: ConfigNode): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP neighbor node |

**Returns:** `string` - The neighbor IP address.

---

#### getBgpGroupName

Get BGP group name from group node.

**Signature:**
```typescript
function getBgpGroupName(node: ConfigNode): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The BGP group node |

**Returns:** `string` - The group name without quotes.

---

### 11. CPM Filter Protection

Functions for validating Control Plane Module (CPM) filter configuration to protect the router control plane.

---

#### hasCpmFilter

Check if CPM filter is configured.

**Signature:**
```typescript
function hasCpmFilter(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The system or security node |

**Returns:** `boolean` - `true` if cpm-filter is configured.

---

#### hasCpmFilterDefaultDrop

Check if CPM filter has default-action drop.

**Signature:**
```typescript
function hasCpmFilterDefaultDrop(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The cpm-filter node |

**Returns:** `boolean` - `true` if default-action is drop.

**Example:**
```typescript
import { hasCpmFilter, hasCpmFilterDefaultDrop } from '@sentriflow/core/helpers/nokia';

if (hasCpmFilter(systemNode)) {
  if (!hasCpmFilterDefaultDrop(cpmFilterNode)) {
    return { passed: false, message: 'CPM filter default-action should be drop' };
  }
}
```

---

#### hasProtocolProtection

Check if protocol protection (CPU protection) is enabled.

**Signature:**
```typescript
function hasProtocolProtection(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The system or security node |

**Returns:** `boolean` - `true` if protocol-protection or cpu-protection is configured.

---

### 12. Data Plane Security

Functions for validating forwarding and data plane security.

---

#### hasUrpf

Check if uRPF (Unicast Reverse Path Forwarding) is configured.

**Signature:**
```typescript
function hasUrpf(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if urpf-check is configured.

---

#### getUrpfMode

Get uRPF mode (strict or loose).

**Signature:**
```typescript
function getUrpfMode(node: ConfigNode): 'strict' | 'loose' | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `'strict' | 'loose' | undefined` - The uRPF mode.

**Example:**
```typescript
import { hasUrpf, getUrpfMode } from '@sentriflow/core/helpers/nokia';

if (hasUrpf(interfaceNode)) {
  const mode = getUrpfMode(interfaceNode);
  if (mode !== 'strict') {
    return { passed: false, message: 'uRPF should be in strict mode' };
  }
}
```

---

#### hasIpFilter

Check if IP filter is applied.

**Signature:**
```typescript
function hasIpFilter(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node |

**Returns:** `boolean` - `true` if ip-filter, ingress filter, or egress filter is configured.

---

### 13. Logging

Functions for validating logging configuration.

---

#### hasSyslog

Check if syslog is configured.

**Signature:**
```typescript
function hasSyslog(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The log or system node |

**Returns:** `boolean` - `true` if syslog is configured.

---

#### hasSnmpTrapGroup

Check if SNMP trap group is configured.

**Signature:**
```typescript
function hasSnmpTrapGroup(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The log or snmp node |

**Returns:** `boolean` - `true` if snmp-trap-group is configured.

---

#### hasEventControl

Check if event-control is configured.

**Signature:**
```typescript
function hasEventControl(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The log node |

**Returns:** `boolean` - `true` if event-control is configured.

---

#### hasAccountingPolicy

Check if accounting policy is configured.

**Signature:**
```typescript
function hasAccountingPolicy(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The log or system node |

**Returns:** `boolean` - `true` if accounting-policy is configured.

---

### 14. High Availability

Functions for validating high availability configuration.

---

#### hasBfd

Check if BFD (Bidirectional Forwarding Detection) is enabled.

**Signature:**
```typescript
function hasBfd(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface or neighbor node |

**Returns:** `boolean` - `true` if bfd-liveness or bfd is configured.

---

#### hasMcLag

Check if MC-LAG (Multi-Chassis LAG) is configured.

**Signature:**
```typescript
function hasMcLag(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The lag or redundancy node |

**Returns:** `boolean` - `true` if mc-lag or multi-chassis is configured.

---

#### hasMcLagAuthentication

Check if MC-LAG authentication is configured.

**Signature:**
```typescript
function hasMcLagAuthentication(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The mc-lag node |

**Returns:** `boolean` - `true` if authentication-key is configured.

---

#### hasLacp

Check if LACP is configured.

**Signature:**
```typescript
function hasLacp(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The lag node |

**Returns:** `boolean` - `true` if lacp is configured.

---

### 15. Service Security (VPN)

Functions for validating MPLS/VPN service security.

---

#### hasRouteDistinguisher

Check if VPRN has route-distinguisher configured.

**Signature:**
```typescript
function hasRouteDistinguisher(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VPRN service node |

**Returns:** `boolean` - `true` if route-distinguisher is configured.

---

#### hasVrfTarget

Check if VPRN has vrf-target configured.

**Signature:**
```typescript
function hasVrfTarget(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VPRN service node |

**Returns:** `boolean` - `true` if vrf-target is configured.

---

#### hasGrtLeaking

Check if GRT leaking is configured (potential security concern).

**Signature:**
```typescript
function hasGrtLeaking(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VPRN service node |

**Returns:** `boolean` - `true` if grt-leaking is configured.

**Example:**
```typescript
import { hasGrtLeaking } from '@sentriflow/core/helpers/nokia';

if (hasGrtLeaking(vprnNode)) {
  return {
    passed: false,
    message: 'GRT leaking should be reviewed - potential routing isolation breach'
  };
}
```

---

## See Also

- [Common Helpers](./common.md) - Platform-agnostic helper functions
- [Juniper Helpers](./juniper.md) - Similar service provider platform (JunOS)
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - Complete guide for writing rules

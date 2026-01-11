# Juniper Helper Functions Reference

Juniper helpers provide specialized functions for validating Juniper JunOS configurations across routers, switches, and SRX firewalls. These helpers understand the hierarchical JunOS configuration syntax and security best practices.

## Import Statement

```typescript
import {
  findStanza,
  findStanzas,
  isSshV2Only,
  hasLoginBanner,
  hasBgpNeighborAuth,
  // ... other helpers
} from '@sentriflow/core/helpers/juniper';
```

Or import everything:

```typescript
import * as juniper from '@sentriflow/core/helpers/juniper';
```

---

## Categories

### 1. Interface Identification

Functions for classifying JunOS interface types.

---

#### isDisabled

Check if a JunOS interface is disabled (has "disable" statement).

**Signature:**
```typescript
function isDisabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface or stanza node to check |

**Returns:** `boolean` - `true` if node has `disable` command.

**Example:**
```typescript
import { isDisabled } from '@sentriflow/core/helpers/juniper';

if (isDisabled(interfaceNode)) {
  return { passed: true, message: 'Interface is disabled - skipping' };
}
```

---

#### isPhysicalJunosPort

Check if interface is a physical port (not lo0, irb, etc.).

**Signature:**
```typescript
function isPhysicalJunosPort(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if physical port.

**Physical Prefixes:** ge-, xe-, et-, ae (aggregated), em, fxp

**Example:**
```typescript
import { isPhysicalJunosPort } from '@sentriflow/core/helpers/juniper';

isPhysicalJunosPort('ge-0/0/0');  // true
isPhysicalJunosPort('xe-0/0/1');  // true
isPhysicalJunosPort('lo0');       // false
isPhysicalJunosPort('irb');       // false
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

**Example:**
```typescript
import { isLoopback } from '@sentriflow/core/helpers/juniper';

isLoopback('lo0');        // true
isLoopback('ge-0/0/0');   // false
```

---

#### isIrbInterface

Check if interface is an IRB (Integrated Routing and Bridging) interface.

**Signature:**
```typescript
function isIrbInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if IRB interface.

**Example:**
```typescript
import { isIrbInterface } from '@sentriflow/core/helpers/juniper';

isIrbInterface('irb.100');  // true
isIrbInterface('ge-0/0/0'); // false
```

---

### 2. Node Navigation

Functions for traversing JunOS hierarchical configuration.

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
| stanzaName | `string` | The stanza name to find (case-insensitive) |

**Returns:** `ConfigNode | undefined` - The matching child node.

**Example:**
```typescript
import { findStanza } from '@sentriflow/core/helpers/juniper';

// Find system stanza
const system = findStanza(rootNode, 'system');

// Find services within system
const services = findStanza(system, 'services');

// Find SSH within services
const ssh = findStanza(services, 'ssh');
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "juniper.findStanza",
  "args": [{ "$ref": "node" }, "system"]
}
```

---

#### findStanzas

Find all stanzas matching a regex pattern.

**Signature:**
```typescript
function findStanzas(node: ConfigNode, pattern: RegExp): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| pattern | `RegExp` | Regex pattern to match (use 'i' flag for case-insensitive) |

**Returns:** `ConfigNode[]` - Array of matching child nodes.

**Example:**
```typescript
import { findStanzas } from '@sentriflow/core/helpers/juniper';

// Find all interface stanzas
const interfaces = findStanzas(ospfAreaNode, /^interface/i);

// Find all groups matching a pattern
const bgpGroups = findStanzas(bgpNode, /^group\s+/i);
```

---

#### getInterfaceUnits

Get all unit sub-interfaces from a JunOS interface node.

**Signature:**
```typescript
function getInterfaceUnits(interfaceNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface node |

**Returns:** `ConfigNode[]` - Array of unit nodes.

**Example:**
```typescript
import { getInterfaceUnits } from '@sentriflow/core/helpers/juniper';

const units = getInterfaceUnits(ge0Node);
// Returns unit 0, unit 100, unit 200, etc.

for (const unit of units) {
  // Check each unit's configuration
}
```

---

#### parseJunosAddress

Parse JunOS address format (e.g., "10.0.0.1/24").

**Signature:**
```typescript
function parseJunosAddress(address: string): { ip: number; prefix: number; mask: number } | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| address | `string` | The address string with CIDR notation |

**Returns:** `{ ip: number; prefix: number; mask: number } | null` - Parsed address or `null`.

**Example:**
```typescript
import { parseJunosAddress } from '@sentriflow/core/helpers/juniper';

const addr = parseJunosAddress('10.0.0.1/24');
// Returns { ip: 167772161, prefix: 24, mask: 4294967040 }
```

---

#### getTermAction

Get the action from a policy-statement term (accept, reject, or next).

**Signature:**
```typescript
function getTermAction(termNode: ConfigNode): 'accept' | 'reject' | 'next' | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| termNode | `ConfigNode` | The term node |

**Returns:** `'accept' | 'reject' | 'next' | undefined` - The term action.

**Example:**
```typescript
import { getTermAction } from '@sentriflow/core/helpers/juniper';

const action = getTermAction(termNode);
if (action === 'accept') {
  // Traffic permitted by this term
}
```

---

#### isFilterTermDrop

Check if a firewall filter term drops traffic (discard or reject).

**Signature:**
```typescript
function isFilterTermDrop(termNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| termNode | `ConfigNode` | The term node |

**Returns:** `boolean` - `true` if term discards or rejects traffic.

**Example:**
```typescript
import { isFilterTermDrop } from '@sentriflow/core/helpers/juniper';

if (isFilterTermDrop(termNode)) {
  // This term blocks traffic
}
```

---

### 3. Management Plane Helpers

Functions for validating management access security.

---

#### isSshV2Only

Check if SSH is configured for version 2 only.

**Signature:**
```typescript
function isSshV2Only(servicesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| servicesNode | `ConfigNode` | The system services node |

**Returns:** `boolean` - `true` if SSH v2 only is configured.

**Example:**
```typescript
import { isSshV2Only, findStanza } from '@sentriflow/core/helpers/juniper';

const system = findStanza(rootNode, 'system');
const services = findStanza(system, 'services');

if (!isSshV2Only(services)) {
  return { passed: false, message: 'SSH should use protocol-version v2' };
}
```

---

#### isSshRootLoginDenied

Check if SSH root login is denied.

**Signature:**
```typescript
function isSshRootLoginDenied(servicesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| servicesNode | `ConfigNode` | The system services node |

**Returns:** `boolean` - `true` if root-login deny is configured.

**Example:**
```typescript
import { isSshRootLoginDenied } from '@sentriflow/core/helpers/juniper';

if (!isSshRootLoginDenied(servicesNode)) {
  return { passed: false, message: 'SSH root-login should be deny' };
}
```

---

#### hasTelnetService

Check if telnet service is configured (insecure).

**Signature:**
```typescript
function hasTelnetService(servicesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| servicesNode | `ConfigNode` | The system services node |

**Returns:** `boolean` - `true` if telnet is enabled.

**Example:**
```typescript
import { hasTelnetService } from '@sentriflow/core/helpers/juniper';

if (hasTelnetService(servicesNode)) {
  return { passed: false, message: 'Telnet should be disabled' };
}
```

---

#### getInsecureServices

Get list of all insecure services that are enabled.

**Signature:**
```typescript
function getInsecureServices(servicesNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| servicesNode | `ConfigNode` | The system services node |

**Returns:** `string[]` - Array of insecure service names.

**Checks for:** telnet, finger, ftp, xnm-clear-text, web-management http

**Example:**
```typescript
import { getInsecureServices } from '@sentriflow/core/helpers/juniper';

const insecure = getInsecureServices(servicesNode);
if (insecure.length > 0) {
  return {
    passed: false,
    message: `Insecure services enabled: ${insecure.join(', ')}`
  };
}
```

---

#### hasTacacsServer

Check if TACACS+ is configured.

**Signature:**
```typescript
function hasTacacsServer(systemNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system node |

**Returns:** `boolean` - `true` if tacplus-server is configured.

---

#### hasRadiusServer

Check if RADIUS is configured.

**Signature:**
```typescript
function hasRadiusServer(systemNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system node |

**Returns:** `boolean` - `true` if radius-server is configured.

---

#### hasAuthenticationOrder

Check if authentication-order is configured.

**Signature:**
```typescript
function hasAuthenticationOrder(systemNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system node |

**Returns:** `boolean` - `true` if authentication-order is configured.

---

#### hasSnmpV3

Check if SNMPv3 is configured.

**Signature:**
```typescript
function hasSnmpV3(snmpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| snmpNode | `ConfigNode` | The snmp node |

**Returns:** `boolean` - `true` if v3 is configured.

---

#### hasNtpAuthentication

Check if NTP authentication is configured.

**Signature:**
```typescript
function hasNtpAuthentication(ntpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ntpNode | `ConfigNode` | The ntp node |

**Returns:** `boolean` - `true` if authentication-key AND trusted-key are configured.

---

#### hasLoginBanner

Check if login banner is configured.

**Signature:**
```typescript
function hasLoginBanner(systemNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system node |

**Returns:** `boolean` - `true` if login message is configured.

**Example:**
```typescript
import { hasLoginBanner, findStanza } from '@sentriflow/core/helpers/juniper';

const system = findStanza(rootNode, 'system');
if (!hasLoginBanner(system)) {
  return { passed: false, message: 'Login banner should be configured' };
}
```

---

#### hasConsoleLogoutOnDisconnect

Check if console log-out-on-disconnect is configured.

**Signature:**
```typescript
function hasConsoleLogoutOnDisconnect(systemNode: ConfigNode): boolean
```

---

#### isAuxPortDisabled

Check if auxiliary port is disabled.

**Signature:**
```typescript
function isAuxPortDisabled(systemNode: ConfigNode): boolean
```

**Returns:** `boolean` - `true` if aux port is disabled or not configured.

---

#### hasLoginRetryOptions

Check if login retry options are configured.

**Signature:**
```typescript
function hasLoginRetryOptions(systemNode: ConfigNode): boolean
```

---

### 4. Control Plane / Routing Helpers

Functions for validating routing protocol security.

---

#### hasOspfInterfaceAuth

Check if OSPF interface has authentication configured.

**Signature:**
```typescript
function hasOspfInterfaceAuth(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The OSPF interface node |

**Returns:** `boolean` - `true` if authentication is configured.

---

#### hasOspfAreaAuth

Check if OSPF area has any authenticated interfaces.

**Signature:**
```typescript
function hasOspfAreaAuth(areaNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| areaNode | `ConfigNode` | The OSPF area node |

**Returns:** `boolean` - `true` if any interface has authentication.

---

#### hasIsisInterfaceAuth

Check if IS-IS interface has hello authentication.

**Signature:**
```typescript
function hasIsisInterfaceAuth(interfaceNode: ConfigNode): boolean
```

---

#### hasVrrpAuth

Check if VRRP group has authentication.

**Signature:**
```typescript
function hasVrrpAuth(vrrpGroupNode: ConfigNode): boolean
```

---

#### hasBfd

Check if BFD is configured for an interface or neighbor.

**Signature:**
```typescript
function hasBfd(node: ConfigNode): boolean
```

**Returns:** `boolean` - `true` if bfd-liveness-detection is configured.

---

### 5. BGP Security Helpers

Functions for validating BGP security configuration.

---

#### hasBgpNeighborAuth

Check if BGP neighbor has authentication-key configured.

**Signature:**
```typescript
function hasBgpNeighborAuth(neighborNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| neighborNode | `ConfigNode` | The BGP neighbor node |

**Returns:** `boolean` - `true` if authentication-key or authentication-key-chain is configured.

**Example:**
```typescript
import { hasBgpNeighborAuth, findStanzas } from '@sentriflow/core/helpers/juniper';

const neighbors = findStanzas(bgpGroupNode, /^neighbor/i);
for (const neighbor of neighbors) {
  if (!hasBgpNeighborAuth(neighbor)) {
    // Flag neighbor without authentication
  }
}
```

---

#### hasBgpGroupAuth

Check if BGP group has authentication configured.

**Signature:**
```typescript
function hasBgpGroupAuth(groupNode: ConfigNode): boolean
```

---

#### hasBgpTtlSecurity

Check if BGP group has TTL security configured (GTSM).

**Signature:**
```typescript
function hasBgpTtlSecurity(groupNode: ConfigNode): boolean
```

**Returns:** `boolean` - `true` if ttl or multihop is configured.

---

#### hasBgpPrefixLimit

Check if BGP group has prefix-limit configured.

**Signature:**
```typescript
function hasBgpPrefixLimit(groupNode: ConfigNode): boolean
```

---

#### hasBgpPolicies

Check if BGP group has import/export policies configured.

**Signature:**
```typescript
function hasBgpPolicies(groupNode: ConfigNode): boolean
```

---

#### isBgpGroupExternal

Check if BGP group type is external (eBGP).

**Signature:**
```typescript
function isBgpGroupExternal(groupNode: ConfigNode): boolean
```

---

#### hasGracefulRestart

Check if graceful-restart is configured.

**Signature:**
```typescript
function hasGracefulRestart(routingOptionsNode: ConfigNode): boolean
```

---

#### hasRpkiValidation

Check if RPKI validation is configured.

**Signature:**
```typescript
function hasRpkiValidation(routingOptionsNode: ConfigNode): boolean
```

---

### 6. Data Plane Helpers

Functions for validating forwarding and interface security.

---

#### hasRpfCheck

Check if interface has rpf-check (uRPF) enabled.

**Signature:**
```typescript
function hasRpfCheck(unitNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| unitNode | `ConfigNode` | The interface unit node |

**Returns:** `boolean` - `true` if rpf-check is configured.

---

#### hasNoRedirects

Check if interface has no-redirects configured.

**Signature:**
```typescript
function hasNoRedirects(unitNode: ConfigNode): boolean
```

---

### 7. Security Zone Helpers (SRX)

Functions for validating SRX zone-based security.

---

#### hasSecurityZones

Check if security zones are configured.

**Signature:**
```typescript
function hasSecurityZones(securityNode: ConfigNode): boolean
```

---

#### hasZoneScreen

Check if zone has screen configured.

**Signature:**
```typescript
function hasZoneScreen(zoneNode: ConfigNode): boolean
```

---

#### getZoneName

Get zone name from a security-zone node.

**Signature:**
```typescript
function getZoneName(zoneNode: ConfigNode): string | undefined
```

---

#### hasSecurityPolicies

Check if security policies are configured.

**Signature:**
```typescript
function hasSecurityPolicies(securityNode: ConfigNode): boolean
```

---

#### hasPolicyLogging

Check if policy has logging enabled.

**Signature:**
```typescript
function hasPolicyLogging(policyNode: ConfigNode): boolean
```

---

### 8. VPN Helpers

Functions for validating IPsec VPN security.

---

#### hasStrongDhGroup

Check if IKE proposal uses strong DH group (group14 or higher).

**Signature:**
```typescript
function hasStrongDhGroup(proposalNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| proposalNode | `ConfigNode` | The IKE proposal node |

**Returns:** `boolean` - `true` if using group14, 15, 16, 19, 20, or 21.

**Weak Groups:** group1, group2, group5

---

#### hasStrongEncryption

Check if IPsec proposal uses strong encryption (AES-256).

**Signature:**
```typescript
function hasStrongEncryption(proposalNode: ConfigNode): boolean
```

**Returns:** `boolean` - `true` if using aes-256 or aes-gcm-256.

---

#### hasDpdEnabled

Check if IKE gateway has dead-peer-detection.

**Signature:**
```typescript
function hasDpdEnabled(gatewayNode: ConfigNode): boolean
```

---

### 9. Routing Engine Protection

Functions for validating RE protection.

---

#### hasLoopbackInputFilter

Check if loopback interface has input filter (protect-RE).

**Signature:**
```typescript
function hasLoopbackInputFilter(interfacesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfacesNode | `ConfigNode` | The interfaces node |

**Returns:** `boolean` - `true` if lo0 unit 0 has filter input configured.

**Example:**
```typescript
import { hasLoopbackInputFilter, findStanza } from '@sentriflow/core/helpers/juniper';

const interfaces = findStanza(rootNode, 'interfaces');
if (!hasLoopbackInputFilter(interfaces)) {
  return { passed: false, message: 'Apply protect-RE filter to lo0' };
}
```

---

### 10. High Availability Helpers

Functions for validating HA configuration.

---

#### hasGres

Check if GRES (Graceful Routing Engine Switchover) is configured.

**Signature:**
```typescript
function hasGres(chassisNode: ConfigNode): boolean
```

---

#### hasNsr

Check if NSR (Nonstop Active Routing) is configured.

**Signature:**
```typescript
function hasNsr(routingOptionsNode: ConfigNode): boolean
```

---

#### hasChassisCluster

Check if chassis cluster is configured (SRX HA).

**Signature:**
```typescript
function hasChassisCluster(chassisNode: ConfigNode): boolean
```

---

#### hasDdosProtection

Check if DDoS protection is configured.

**Signature:**
```typescript
function hasDdosProtection(systemNode: ConfigNode): boolean
```

---

### 11. Logging Helpers

Functions for validating logging configuration.

---

#### hasRemoteSyslog

Check if remote syslog host is configured.

**Signature:**
```typescript
function hasRemoteSyslog(syslogNode: ConfigNode): boolean
```

---

#### hasSyslogArchive

Check if syslog file archiving is configured.

**Signature:**
```typescript
function hasSyslogArchive(syslogNode: ConfigNode): boolean
```

---

#### hasSecurityLogging

Check if security logging is configured (SRX).

**Signature:**
```typescript
function hasSecurityLogging(securityNode: ConfigNode): boolean
```

---

#### hasFlowMonitoring

Check if J-Flow/NetFlow sampling is configured.

**Signature:**
```typescript
function hasFlowMonitoring(forwardingOptionsNode: ConfigNode): boolean
```

---

### 12. Security Screen Helpers

Functions for validating security screens.

---

#### hasScreenTcpProtection

Check if screen has TCP protections.

**Signature:**
```typescript
function hasScreenTcpProtection(screenNode: ConfigNode): boolean
```

---

#### hasScreenIpProtection

Check if screen has IP protections.

**Signature:**
```typescript
function hasScreenIpProtection(screenNode: ConfigNode): boolean
```

---

#### hasScreenIcmpProtection

Check if screen has ICMP protections.

**Signature:**
```typescript
function hasScreenIcmpProtection(screenNode: ConfigNode): boolean
```

---

## See Also

- [Helper Functions Overview](./README.md)
- [Common Helpers](./common.md)
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md)

# VyOS/EdgeOS Helper Functions Reference

VyOS helpers provide specialized functions for validating VyOS and Ubiquiti EdgeOS router configurations. VyOS is an open-source network operating system based on Debian that provides software-based routing, firewall, and VPN functionality. EdgeOS is Ubiquiti's derivative used in their EdgeRouter product line. Both share similar hierarchical configuration syntax derived from the Vyatta project.

These helpers understand the hierarchical configuration syntax used by VyOS/EdgeOS and provide utilities for interface classification, firewall validation, service configuration checks, and navigation through configuration trees.

## Import Statement

```typescript
import {
  findStanza,
  findStanzas,
  isDisabled,
  getFirewallDefaultAction,
  parseVyosAddress,
  // ... other helpers
} from '@sentriflow/core/helpers/vyos';
```

Or import everything:

```typescript
import * as vyos from '@sentriflow/core/helpers/vyos';
```

---

## Categories

### 1. Interface Identification

Functions for classifying VyOS/EdgeOS interface types.

---

#### isDisabled

Check if a VyOS interface or node is disabled (has "disable" statement).

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
import { isDisabled } from '@sentriflow/core/helpers/vyos';

if (isDisabled(interfaceNode)) {
  return { passed: true, message: 'Interface is disabled - skipping' };
}
```

---

#### isPhysicalVyosPort

Check if interface is a physical ethernet port (ethX).

**Signature:**
```typescript
function isPhysicalVyosPort(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if physical ethernet port.

**Physical Patterns:** `ethernet ethX`, `ethX`

**Example:**
```typescript
import { isPhysicalVyosPort } from '@sentriflow/core/helpers/vyos';

isPhysicalVyosPort('ethernet eth0');  // true
isPhysicalVyosPort('eth1');           // true
isPhysicalVyosPort('lo');             // false
isPhysicalVyosPort('bond0');          // false
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
import { isLoopback } from '@sentriflow/core/helpers/vyos';

isLoopback('loopback lo');  // true
isLoopback('lo');           // true
isLoopback('eth0');         // false
```

---

#### isBondingInterface

Check if interface is a bonding (link aggregation) interface.

**Signature:**
```typescript
function isBondingInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if bonding interface.

**Example:**
```typescript
import { isBondingInterface } from '@sentriflow/core/helpers/vyos';

isBondingInterface('bonding bond0');  // true
isBondingInterface('bond0');          // true
isBondingInterface('eth0');           // false
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

**Returns:** `boolean` - `true` if bridge interface.

**Example:**
```typescript
import { isBridgeInterface } from '@sentriflow/core/helpers/vyos';

isBridgeInterface('bridge br0');  // true
isBridgeInterface('br0');         // true
isBridgeInterface('eth0');        // false
```

---

#### isWireGuardInterface

Check if interface is a WireGuard VPN interface.

**Signature:**
```typescript
function isWireGuardInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if WireGuard interface.

**Example:**
```typescript
import { isWireGuardInterface } from '@sentriflow/core/helpers/vyos';

isWireGuardInterface('wireguard wg0');  // true
isWireGuardInterface('wg0');            // true
isWireGuardInterface('eth0');           // false
```

---

#### isTunnelInterface

Check if interface is a tunnel interface (GRE, VTI, VXLAN).

**Signature:**
```typescript
function isTunnelInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if tunnel interface.

**Detected Types:** tunnel, vti (VPN Tunnel Interface), vxlan, tun

**Example:**
```typescript
import { isTunnelInterface } from '@sentriflow/core/helpers/vyos';

isTunnelInterface('tunnel tun0');  // true
isTunnelInterface('vti0');         // true
isTunnelInterface('vxlan0');       // true
isTunnelInterface('eth0');         // false
```

---

### 2. Address Parsing

Functions for parsing VyOS address formats.

---

#### parseVyosAddress

Parse VyOS address format with CIDR notation (e.g., "10.0.0.1/24").

**Signature:**
```typescript
function parseVyosAddress(address: string): { ip: number; prefix: number; mask: number } | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| address | `string` | The address string with CIDR notation |

**Returns:** `{ ip: number; prefix: number; mask: number } | null` - Parsed address object or `null` if invalid.

**Properties:**
- `ip`: The IP address as a 32-bit integer
- `prefix`: The CIDR prefix length (0-32)
- `mask`: The subnet mask as a 32-bit integer

**Example:**
```typescript
import { parseVyosAddress } from '@sentriflow/core/helpers/vyos';

const addr = parseVyosAddress('10.0.0.1/24');
// Returns { ip: 167772161, prefix: 24, mask: 4294967040 }

const invalid = parseVyosAddress('invalid');
// Returns null
```

---

### 3. Node Navigation

Functions for traversing VyOS hierarchical configuration trees.

---

#### findStanza

Find a stanza by exact name within a node's children.

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
import { findStanza } from '@sentriflow/core/helpers/vyos';

// Find interfaces stanza
const interfaces = findStanza(rootNode, 'interfaces');

// Find firewall stanza
const firewall = findStanza(rootNode, 'firewall');

// Find service stanza
const service = findStanza(rootNode, 'service');
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "vyos.findStanza",
  "args": [{ "$ref": "node" }, "firewall"]
}
```

---

#### findStanzaByPrefix

Find the first stanza that starts with a given prefix.

**Signature:**
```typescript
function findStanzaByPrefix(node: ConfigNode, prefix: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| prefix | `string` | The prefix to match (case-insensitive) |

**Returns:** `ConfigNode | undefined` - The first matching child node.

**Example:**
```typescript
import { findStanzaByPrefix } from '@sentriflow/core/helpers/vyos';

// Find first ethernet interface
const eth = findStanzaByPrefix(interfacesNode, 'ethernet eth');

// Find first firewall rule
const rule = findStanzaByPrefix(rulesetNode, 'rule');
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
| pattern | `RegExp` | Regex pattern to match against child node IDs |

**Returns:** `ConfigNode[]` - Array of matching child nodes.

**Example:**
```typescript
import { findStanzas } from '@sentriflow/core/helpers/vyos';

// Find all ethernet interfaces
const ethInterfaces = findStanzas(interfacesNode, /^ethernet eth\d+$/i);

// Find all firewall rules
const rules = findStanzas(rulesetNode, /^rule \d+$/i);

// Find all NAT rules
const natRules = findStanzas(natNode, /^rule/i);
```

---

#### findStanzasByPrefix

Find all stanzas that start with a given prefix.

**Signature:**
```typescript
function findStanzasByPrefix(node: ConfigNode, prefix: string): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| prefix | `string` | The prefix to match (case-insensitive) |

**Returns:** `ConfigNode[]` - Array of matching child nodes.

**Example:**
```typescript
import { findStanzasByPrefix } from '@sentriflow/core/helpers/vyos';

// Find all ethernet interfaces
const ethInterfaces = findStanzasByPrefix(interfacesNode, 'ethernet eth');

// Find all VIF sub-interfaces
const vifs = findStanzasByPrefix(interfaceNode, 'vif');
```

---

### 4. Interface Helpers

Functions for working with VyOS interface configurations.

---

#### getEthernetInterfaces

Get all ethernet interfaces from the interfaces node.

**Signature:**
```typescript
function getEthernetInterfaces(interfacesNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfacesNode | `ConfigNode` | The interfaces ConfigNode |

**Returns:** `ConfigNode[]` - Array of ethernet interface nodes.

**Example:**
```typescript
import { getEthernetInterfaces, findStanza } from '@sentriflow/core/helpers/vyos';

const interfaces = findStanza(rootNode, 'interfaces');
const ethPorts = getEthernetInterfaces(interfaces);

for (const eth of ethPorts) {
  // Check each ethernet interface configuration
  console.log(eth.id);  // "ethernet eth0", "ethernet eth1", etc.
}
```

---

#### getVifInterfaces

Get VIF (VLAN) sub-interfaces from an interface node.

**Signature:**
```typescript
function getVifInterfaces(interfaceNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `ConfigNode[]` - Array of VIF sub-interface nodes.

**Example:**
```typescript
import { getVifInterfaces, getEthernetInterfaces, findStanza } from '@sentriflow/core/helpers/vyos';

const interfaces = findStanza(rootNode, 'interfaces');
const ethPorts = getEthernetInterfaces(interfaces);

for (const eth of ethPorts) {
  const vlans = getVifInterfaces(eth);
  for (const vlan of vlans) {
    console.log(vlan.id);  // "vif 10", "vif 20", etc.
  }
}
```

---

### 5. Aggregation Member Helpers

Functions for identifying interfaces that are members of aggregated or virtual interfaces. Member interfaces do not need individual IP addresses since the parent interface holds the address.

---

#### getSwitchPortMembers

Get all interfaces that are members of a switch (switch-port). These interfaces are part of a layer-2 switching domain.

**Signature:**
```typescript
function getSwitchPortMembers(interfacesNode: ConfigNode): Set<string>
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfacesNode | `ConfigNode` | The interfaces ConfigNode |

**Returns:** `Set<string>` - Set of interface names (e.g., 'eth1', 'eth2') that are switch members.

**Example:**
```typescript
import { getSwitchPortMembers, findStanza } from '@sentriflow/core/helpers/vyos';

const interfaces = findStanza(rootNode, 'interfaces');
const switchMembers = getSwitchPortMembers(interfaces);

// Check if an interface is a switch member
if (switchMembers.has('eth1')) {
  return { passed: true, message: 'Interface is switch member - no IP needed' };
}
```

---

#### getBridgeMembers

Get all interfaces that are members of a bridge. These interfaces operate at layer-2 and do not need individual IP addresses.

**Signature:**
```typescript
function getBridgeMembers(interfacesNode: ConfigNode): Set<string>
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfacesNode | `ConfigNode` | The interfaces ConfigNode |

**Returns:** `Set<string>` - Set of interface names that are bridge members.

**Example:**
```typescript
import { getBridgeMembers, findStanza } from '@sentriflow/core/helpers/vyos';

const interfaces = findStanza(rootNode, 'interfaces');
const bridgeMembers = getBridgeMembers(interfaces);

for (const member of bridgeMembers) {
  console.log(`${member} is a bridge member`);
}
```

---

#### getBondingMembers

Get all interfaces that are members of a bonding group (link aggregation). These interfaces are aggregated into a single logical interface.

**Signature:**
```typescript
function getBondingMembers(interfacesNode: ConfigNode): Set<string>
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfacesNode | `ConfigNode` | The interfaces ConfigNode |

**Returns:** `Set<string>` - Set of interface names that are bonding members.

**Example:**
```typescript
import { getBondingMembers, findStanza } from '@sentriflow/core/helpers/vyos';

const interfaces = findStanza(rootNode, 'interfaces');
const bondMembers = getBondingMembers(interfaces);

// Skip member interfaces when checking for IP configuration
if (bondMembers.has('eth0')) {
  return { passed: true, message: 'Interface is bonding member - IP on bond' };
}
```

---

### 6. Firewall Helpers

Functions for validating VyOS firewall configurations.

---

#### getFirewallDefaultAction

Get the default action of a firewall ruleset.

**Signature:**
```typescript
function getFirewallDefaultAction(rulesetNode: ConfigNode): 'drop' | 'accept' | 'reject' | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rulesetNode | `ConfigNode` | The firewall ruleset (name X) ConfigNode |

**Returns:** `'drop' | 'accept' | 'reject' | undefined` - The default action or `undefined` if not set.

**Example:**
```typescript
import { getFirewallDefaultAction, findStanza } from '@sentriflow/core/helpers/vyos';

const firewall = findStanza(rootNode, 'firewall');
const ruleset = findStanza(firewall, 'name WAN_IN');

const defaultAction = getFirewallDefaultAction(ruleset);
if (defaultAction !== 'drop') {
  return {
    passed: false,
    message: 'Firewall default action should be drop'
  };
}
```

---

#### getFirewallRules

Get all firewall rules from a ruleset.

**Signature:**
```typescript
function getFirewallRules(rulesetNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rulesetNode | `ConfigNode` | The firewall ruleset ConfigNode |

**Returns:** `ConfigNode[]` - Array of rule nodes.

**Example:**
```typescript
import { getFirewallRules, findStanza } from '@sentriflow/core/helpers/vyos';

const firewall = findStanza(rootNode, 'firewall');
const ruleset = findStanza(firewall, 'name WAN_IN');
const rules = getFirewallRules(ruleset);

for (const rule of rules) {
  console.log(rule.id);  // "rule 10", "rule 20", etc.
}
```

---

#### getFirewallRuleAction

Get the action of a specific firewall rule.

**Signature:**
```typescript
function getFirewallRuleAction(ruleNode: ConfigNode): 'drop' | 'accept' | 'reject' | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The firewall rule ConfigNode |

**Returns:** `'drop' | 'accept' | 'reject' | undefined` - The rule action or `undefined` if not set.

**Example:**
```typescript
import { getFirewallRuleAction, getFirewallRules, findStanza } from '@sentriflow/core/helpers/vyos';

const firewall = findStanza(rootNode, 'firewall');
const ruleset = findStanza(firewall, 'name WAN_IN');
const rules = getFirewallRules(ruleset);

for (const rule of rules) {
  const action = getFirewallRuleAction(rule);
  if (action === 'accept') {
    // Check what traffic is being allowed
  }
}
```

---

### 7. NAT Helpers

Functions for validating NAT configurations.

---

#### hasNatTranslation

Check if a NAT rule has translation configured.

**Signature:**
```typescript
function hasNatTranslation(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The NAT rule ConfigNode |

**Returns:** `boolean` - `true` if translation is configured.

**Example:**
```typescript
import { hasNatTranslation, findStanzas, findStanza } from '@sentriflow/core/helpers/vyos';

const nat = findStanza(rootNode, 'nat');
const source = findStanza(nat, 'source');
const rules = findStanzas(source, /^rule/i);

for (const rule of rules) {
  if (!hasNatTranslation(rule)) {
    return { passed: false, message: 'NAT rule missing translation' };
  }
}
```

---

### 8. Service Helpers

Functions for validating VyOS service configurations.

---

#### hasSshService

Check if SSH service is configured.

**Signature:**
```typescript
function hasSshService(serviceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| serviceNode | `ConfigNode` | The service ConfigNode |

**Returns:** `boolean` - `true` if SSH is configured.

**Example:**
```typescript
import { hasSshService, findStanza } from '@sentriflow/core/helpers/vyos';

const service = findStanza(rootNode, 'service');
if (!hasSshService(service)) {
  return { passed: false, message: 'SSH service should be configured for management' };
}
```

---

#### getSshConfig

Get the SSH configuration node from service.

**Signature:**
```typescript
function getSshConfig(serviceNode: ConfigNode): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| serviceNode | `ConfigNode` | The service ConfigNode |

**Returns:** `ConfigNode | undefined` - The SSH configuration node.

**Example:**
```typescript
import { getSshConfig, findStanza, hasChildCommand } from '@sentriflow/core/helpers/vyos';

const service = findStanza(rootNode, 'service');
const sshConfig = getSshConfig(service);

if (sshConfig) {
  // Check for password authentication (should be disabled)
  if (!hasChildCommand(sshConfig, 'disable-password-authentication')) {
    return { passed: false, message: 'SSH password auth should be disabled' };
  }
}
```

---

#### hasDhcpServer

Check if DHCP server is configured.

**Signature:**
```typescript
function hasDhcpServer(serviceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| serviceNode | `ConfigNode` | The service ConfigNode |

**Returns:** `boolean` - `true` if DHCP server is configured.

---

#### getDnsConfig

Get DNS forwarding configuration.

**Signature:**
```typescript
function getDnsConfig(serviceNode: ConfigNode): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| serviceNode | `ConfigNode` | The service ConfigNode |

**Returns:** `ConfigNode | undefined` - The DNS configuration node.

**Example:**
```typescript
import { getDnsConfig, findStanza } from '@sentriflow/core/helpers/vyos';

const service = findStanza(rootNode, 'service');
const dnsConfig = getDnsConfig(service);

if (dnsConfig) {
  // Check DNS forwarding settings
}
```

---

### 9. System Helpers

Functions for validating VyOS system configurations.

---

#### hasNtpConfig

Check if NTP is configured for time synchronization.

**Signature:**
```typescript
function hasNtpConfig(systemNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system ConfigNode |

**Returns:** `boolean` - `true` if NTP is configured.

**Example:**
```typescript
import { hasNtpConfig, findStanza } from '@sentriflow/core/helpers/vyos';

const system = findStanza(rootNode, 'system');
if (!hasNtpConfig(system)) {
  return { passed: false, message: 'NTP should be configured for accurate timestamps' };
}
```

---

#### hasSyslogConfig

Check if syslog is configured for logging.

**Signature:**
```typescript
function hasSyslogConfig(systemNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system ConfigNode |

**Returns:** `boolean` - `true` if syslog is configured.

**Example:**
```typescript
import { hasSyslogConfig, findStanza } from '@sentriflow/core/helpers/vyos';

const system = findStanza(rootNode, 'system');
if (!hasSyslogConfig(system)) {
  return { passed: false, message: 'Syslog should be configured for audit logging' };
}
```

---

#### getLoginConfig

Get the login configuration from system node.

**Signature:**
```typescript
function getLoginConfig(systemNode: ConfigNode): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system ConfigNode |

**Returns:** `ConfigNode | undefined` - The login configuration node.

**Example:**
```typescript
import { getLoginConfig, findStanza } from '@sentriflow/core/helpers/vyos';

const system = findStanza(rootNode, 'system');
const loginConfig = getLoginConfig(system);

if (loginConfig) {
  // Check user configurations
}
```

---

#### getUserConfigs

Get all user configurations from the login node.

**Signature:**
```typescript
function getUserConfigs(loginNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| loginNode | `ConfigNode` | The login ConfigNode |

**Returns:** `ConfigNode[]` - Array of user configuration nodes.

**Example:**
```typescript
import { getUserConfigs, getLoginConfig, findStanza } from '@sentriflow/core/helpers/vyos';

const system = findStanza(rootNode, 'system');
const loginConfig = getLoginConfig(system);
const users = getUserConfigs(loginConfig);

for (const user of users) {
  console.log(user.id);  // "user admin", "user readonly", etc.
  // Check user authentication settings
}
```

---

### 10. Re-exported Common Helpers

The following helpers are re-exported from the common helpers module for convenience.

---

#### hasChildCommand

Check if a node has a child with a specific command.

**Signature:**
```typescript
function hasChildCommand(node: ConfigNode, command: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| command | `string` | The command string to find (case-insensitive) |

**Returns:** `boolean` - `true` if the command exists as a child.

---

#### getChildCommand

Get a child node by command name.

**Signature:**
```typescript
function getChildCommand(node: ConfigNode, command: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| command | `string` | The command string to find (case-insensitive) |

**Returns:** `ConfigNode | undefined` - The matching child node.

---

#### getChildCommands

Get all child nodes matching a command pattern.

**Signature:**
```typescript
function getChildCommands(node: ConfigNode, pattern: RegExp): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| pattern | `RegExp` | The regex pattern to match |

**Returns:** `ConfigNode[]` - Array of matching child nodes.

---

#### parseIp

Parse an IP address string to a 32-bit integer.

**Signature:**
```typescript
function parseIp(ip: string): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ip | `string` | The IP address string |

**Returns:** `number | null` - The IP as a 32-bit integer or `null` if invalid.

---

## VyOS Configuration Structure

VyOS configurations follow a hierarchical structure. Understanding this structure helps when writing rules:

```
interfaces {
    ethernet eth0 {
        address 192.168.1.1/24
        description "WAN"
    }
    ethernet eth1 {
        address 10.0.0.1/24
        vif 10 {
            address 10.10.0.1/24
        }
    }
}
firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
            state {
                established enable
                related enable
            }
        }
    }
}
service {
    ssh {
        port 22
    }
}
system {
    login {
        user admin {
            authentication {
                encrypted-password $6$...
            }
        }
    }
    ntp {
        server pool.ntp.org
    }
    syslog {
        host 10.0.0.100
    }
}
```

---

## See Also

- [Helper Functions Overview](./README.md)
- [Common Helpers](./common.md)
- [Juniper Helpers](./juniper.md) - Similar hierarchical configuration structure
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md)

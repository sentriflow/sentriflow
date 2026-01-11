# MikroTik RouterOS Helper Functions Reference

MikroTik helpers provide specialized functions for validating MikroTik RouterOS router and switch configurations. These helpers understand MikroTik-specific syntax, command structures, property-value pairs, and security best practices for RouterOS versions 6 and 7.

MikroTik RouterOS uses a hierarchical command structure with paths (like `/ip firewall filter`) and property-value pairs (like `disabled=yes`). The helpers in this module are designed to parse and validate these structures efficiently.

## Import Statement

```typescript
import {
  isPhysicalInterface,
  parseProperty,
  getFirewallChain,
  hasBridgeVlanFiltering,
  // ... other helpers
} from '@sentriflow/core/helpers/mikrotik';
```

Or import everything:

```typescript
import * as mikrotik from '@sentriflow/core/helpers/mikrotik';
```

---

## Categories

### 1. Resource Status Helpers

Functions for checking the status of MikroTik resources.

---

#### isDisabledResource

Check if a MikroTik resource is disabled (has `disabled=yes` property).

**Signature:**
```typescript
function isDisabledResource(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string to check |

**Returns:** `boolean` - `true` if resource has `disabled=yes`.

**Example:**
```typescript
import { isDisabledResource } from '@sentriflow/core/helpers/mikrotik';

isDisabledResource('add address=192.168.1.1/24 disabled=yes');  // true
isDisabledResource('add address=192.168.1.1/24');               // false
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "mikrotik.isDisabledResource",
  "args": [{ "$ref": "node" }]
}
```

---

#### isEnabled

Check if a feature is enabled (common `enabled=yes` pattern).

**Signature:**
```typescript
function isEnabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string to check |

**Returns:** `boolean` - `true` if `enabled=yes` is present.

**Example:**
```typescript
import { isEnabled } from '@sentriflow/core/helpers/mikrotik';

isEnabled('set enabled=yes');  // true
isEnabled('set enabled=no');   // false
```

---

### 2. Interface Identification

Functions for classifying MikroTik interface types.

---

#### isPhysicalInterface

Check if interface is a physical ethernet port (ether1, ether2, sfp1, etc.).

**Signature:**
```typescript
function isPhysicalInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if physical port, `false` for virtual interfaces.

**Matched Patterns:** `ether*`, `sfp*`, `sfp-sfpplus*`, `combo*`, `qsfp*`

**Example:**
```typescript
import { isPhysicalInterface } from '@sentriflow/core/helpers/mikrotik';

isPhysicalInterface('ether1');       // true
isPhysicalInterface('sfp-sfpplus1'); // true
isPhysicalInterface('bridge1');      // false
isPhysicalInterface('vlan100');      // false
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "mikrotik.isPhysicalInterface",
  "args": [{ "$ref": "node.id" }]
}
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
import { isLoopback } from '@sentriflow/core/helpers/mikrotik';

isLoopback('lo');         // true
isLoopback('loopback1');  // true
isLoopback('ether1');     // false
```

---

#### isBridgeInterface

Check if interface is a bridge.

**Signature:**
```typescript
function isBridgeInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if bridge interface.

**Matched Patterns:** `bridge*`, `br*` (followed by digits)

**Example:**
```typescript
import { isBridgeInterface } from '@sentriflow/core/helpers/mikrotik';

isBridgeInterface('bridge1');  // true
isBridgeInterface('br0');      // true
isBridgeInterface('ether1');   // false
```

---

#### isVlanInterface

Check if interface is a VLAN.

**Signature:**
```typescript
function isVlanInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if VLAN interface.

**Example:**
```typescript
import { isVlanInterface } from '@sentriflow/core/helpers/mikrotik';

isVlanInterface('vlan100');  // true
isVlanInterface('vlan10');   // true
isVlanInterface('ether1');   // false
```

---

#### isBondingInterface

Check if interface is a bonding (LAG).

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
import { isBondingInterface } from '@sentriflow/core/helpers/mikrotik';

isBondingInterface('bonding1');  // true
isBondingInterface('bond0');     // true
isBondingInterface('ether1');    // false
```

---

#### isWireGuardInterface

Check if interface is WireGuard.

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
import { isWireGuardInterface } from '@sentriflow/core/helpers/mikrotik';

isWireGuardInterface('wireguard1');  // true
isWireGuardInterface('wg0');         // true
isWireGuardInterface('ether1');      // false
```

---

#### isTunnelInterface

Check if interface is a tunnel type (EoIP, GRE, IPIP, L2TP, PPTP, SSTP, OpenVPN, PPPoE, VXLAN).

**Signature:**
```typescript
function isTunnelInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if tunnel interface.

**Matched Prefixes:** `eoip`, `gre`, `ipip`, `vxlan`, `l2tp`, `pptp`, `sstp`, `ovpn`, `pppoe`

**Example:**
```typescript
import { isTunnelInterface } from '@sentriflow/core/helpers/mikrotik';

isTunnelInterface('eoip-tunnel1');   // true
isTunnelInterface('gre-tunnel1');    // true
isTunnelInterface('pppoe-out1');     // true
isTunnelInterface('ether1');         // false
```

---

### 3. Property Parsing

Functions for extracting and checking MikroTik property values.

---

#### parseProperty

Parse a MikroTik property value from a command string.

**Signature:**
```typescript
function parseProperty(commandStr: string, propertyName: string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| commandStr | `string` | The command string to parse |
| propertyName | `string` | The property name to find |

**Returns:** `string | undefined` - The property value or `undefined` if not found.

**Notes:** Handles quoted values (`"value"` or `'value'`) and unquoted values.

**Example:**
```typescript
import { parseProperty } from '@sentriflow/core/helpers/mikrotik';

parseProperty('add address=192.168.1.1/24 interface=LAN', 'address');
// Returns: '192.168.1.1/24'

parseProperty('add comment="Main gateway" disabled=no', 'comment');
// Returns: 'Main gateway'

parseProperty('add address=10.0.0.1/24', 'interface');
// Returns: undefined
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "mikrotik.parseProperty",
  "args": [{ "$ref": "node.id" }, "address"]
}
```

---

#### hasProperty

Check if a command/node has a specific property.

**Signature:**
```typescript
function hasProperty(nodeOrCommand: ConfigNode | string, propertyName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |
| propertyName | `string` | The property name to check |

**Returns:** `boolean` - `true` if property exists.

**Example:**
```typescript
import { hasProperty } from '@sentriflow/core/helpers/mikrotik';

hasProperty('add address=192.168.1.1/24 interface=LAN', 'interface');  // true
hasProperty('add address=192.168.1.1/24', 'interface');                 // false
```

---

#### getName

Get the `name` property from a command.

**Signature:**
```typescript
function getName(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The name value or `undefined`.

**Example:**
```typescript
import { getName } from '@sentriflow/core/helpers/mikrotik';

getName('add name=LAN-Bridge vlan-filtering=yes');  // 'LAN-Bridge'
```

---

#### getComment

Get the `comment` property from a command.

**Signature:**
```typescript
function getComment(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The comment value or `undefined`.

**Example:**
```typescript
import { getComment } from '@sentriflow/core/helpers/mikrotik';

getComment('add address=192.168.1.1/24 comment="Main router"');  // 'Main router'
```

---

#### getInterface

Get the interface from a command. Checks `interface=`, `in-interface=`, and `out-interface=`.

**Signature:**
```typescript
function getInterface(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The interface name or `undefined`.

**Example:**
```typescript
import { getInterface } from '@sentriflow/core/helpers/mikrotik';

getInterface('add address=192.168.1.1/24 interface=ether1');  // 'ether1'
getInterface('add chain=forward in-interface=WAN');           // 'WAN'
```

---

#### getInInterface

Get the `in-interface` from a rule.

**Signature:**
```typescript
function getInInterface(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The in-interface name or `undefined`.

**Example:**
```typescript
import { getInInterface } from '@sentriflow/core/helpers/mikrotik';

getInInterface('add chain=forward in-interface=WAN action=drop');  // 'WAN'
```

---

#### getOutInterface

Get the `out-interface` from a rule.

**Signature:**
```typescript
function getOutInterface(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The out-interface name or `undefined`.

**Example:**
```typescript
import { getOutInterface } from '@sentriflow/core/helpers/mikrotik';

getOutInterface('add chain=srcnat out-interface=WAN action=masquerade');  // 'WAN'
```

---

### 4. Command Detection

Functions for identifying command types.

---

#### isAddCommand

Check if a command is an `add` command.

**Signature:**
```typescript
function isAddCommand(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `add` command.

**Example:**
```typescript
import { isAddCommand } from '@sentriflow/core/helpers/mikrotik';

isAddCommand('add address=192.168.1.1/24 interface=LAN');  // true
isAddCommand('set enabled=yes');                            // false
```

---

#### isSetCommand

Check if a command is a `set` command.

**Signature:**
```typescript
function isSetCommand(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `set` command.

**Example:**
```typescript
import { isSetCommand } from '@sentriflow/core/helpers/mikrotik';

isSetCommand('set enabled=yes');                            // true
isSetCommand('add address=192.168.1.1/24 interface=LAN');  // false
```

---

#### getAddCommands

Get all `add` commands from a node's children.

**Signature:**
```typescript
function getAddCommands(node: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node |

**Returns:** `ConfigNode[]` - Array of child nodes that are `add` commands.

**Example:**
```typescript
import { getAddCommands } from '@sentriflow/core/helpers/mikrotik';

const rules = getAddCommands(firewallFilterNode);
// Returns all firewall rules (add commands) from /ip firewall filter
```

---

#### getSetCommands

Get all `set` commands from a node's children.

**Signature:**
```typescript
function getSetCommands(node: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node |

**Returns:** `ConfigNode[]` - Array of child nodes that are `set` commands.

**Example:**
```typescript
import { getSetCommands } from '@sentriflow/core/helpers/mikrotik';

const settings = getSetCommands(systemNode);
```

---

### 5. Path/Block Navigation

Functions for navigating MikroTik configuration hierarchy.

---

#### isPathBlock

Check if a path block matches a specific path.

**Signature:**
```typescript
function isPathBlock(node: ConfigNode, path: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The node to check |
| path | `string` | The path to match (e.g., `/ip firewall filter`) |

**Returns:** `boolean` - `true` if node matches the path.

**Example:**
```typescript
import { isPathBlock } from '@sentriflow/core/helpers/mikrotik';

isPathBlock(node, '/ip firewall filter');  // true if node.id is '/ip firewall filter'
```

---

#### findPathBlock

Find a child node that matches a path pattern.

**Signature:**
```typescript
function findPathBlock(node: ConfigNode, pathPrefix: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| pathPrefix | `string` | The path prefix to match |

**Returns:** `ConfigNode | undefined` - The matching child node or `undefined`.

**Example:**
```typescript
import { findPathBlock } from '@sentriflow/core/helpers/mikrotik';

const firewallFilter = findPathBlock(rootNode, '/ip firewall filter');
```

---

#### findPathBlocks

Find all child nodes that match a path pattern.

**Signature:**
```typescript
function findPathBlocks(node: ConfigNode, pathPrefix: string): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| pathPrefix | `string` | The path prefix to match |

**Returns:** `ConfigNode[]` - Array of matching child nodes.

**Example:**
```typescript
import { findPathBlocks } from '@sentriflow/core/helpers/mikrotik';

const allFirewallSections = findPathBlocks(rootNode, '/ip firewall');
// Returns /ip firewall filter, /ip firewall nat, /ip firewall mangle, etc.
```

---

### 6. Address Parsing

Functions for parsing MikroTik address formats.

---

#### parseMikroTikAddress

Parse MikroTik address format (e.g., `192.168.1.1/24`).

**Signature:**
```typescript
function parseMikroTikAddress(address: string): { ip: number; prefix: number; mask: number } | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| address | `string` | The address string with CIDR notation |

**Returns:** `{ ip: number; prefix: number; mask: number } | null` - Parsed address object or `null` if invalid.

**Example:**
```typescript
import { parseMikroTikAddress } from '@sentriflow/core/helpers/mikrotik';

const addr = parseMikroTikAddress('192.168.1.1/24');
// Returns: { ip: 3232235777, prefix: 24, mask: 4294967040 }

parseMikroTikAddress('invalid');  // null
```

---

### 7. Firewall Helpers

Functions for analyzing MikroTik firewall configuration.

---

#### getFirewallChain

Get the firewall chain from a firewall rule command.

**Signature:**
```typescript
function getFirewallChain(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The chain name (e.g., `input`, `forward`, `output`).

**Example:**
```typescript
import { getFirewallChain } from '@sentriflow/core/helpers/mikrotik';

getFirewallChain('add chain=input action=drop');  // 'input'
```

---

#### getFirewallAction

Get the firewall action from a firewall rule command.

**Signature:**
```typescript
function getFirewallAction(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The action (e.g., `accept`, `drop`, `reject`).

**Example:**
```typescript
import { getFirewallAction } from '@sentriflow/core/helpers/mikrotik';

getFirewallAction('add chain=input action=drop');  // 'drop'
```

---

#### getFirewallRules

Get all firewall rules from a firewall path block.

**Signature:**
```typescript
function getFirewallRules(firewallNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| firewallNode | `ConfigNode` | The firewall section node |

**Returns:** `ConfigNode[]` - Array of firewall rule nodes.

**Example:**
```typescript
import { getFirewallRules, findPathBlock } from '@sentriflow/core/helpers/mikrotik';

const filterBlock = findPathBlock(root, '/ip firewall filter');
const rules = getFirewallRules(filterBlock);
```

---

#### getConnectionStates

Get connection states from a firewall rule.

**Signature:**
```typescript
function getConnectionStates(nodeOrCommand: ConfigNode | string): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string[]` - Array of connection states.

**Example:**
```typescript
import { getConnectionStates } from '@sentriflow/core/helpers/mikrotik';

getConnectionStates('add chain=input connection-state=established,related action=accept');
// Returns: ['established', 'related']
```

---

#### hasStatefulTracking

Check if a firewall rule has stateful tracking (established, related).

**Signature:**
```typescript
function hasStatefulTracking(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if stateful tracking is configured.

**Example:**
```typescript
import { hasStatefulTracking } from '@sentriflow/core/helpers/mikrotik';

hasStatefulTracking('add chain=input connection-state=established,related action=accept');
// Returns: true
```

---

#### hasFirewallLogging

Check if firewall rule has logging enabled.

**Signature:**
```typescript
function hasFirewallLogging(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `log=yes` is present.

**Example:**
```typescript
import { hasFirewallLogging } from '@sentriflow/core/helpers/mikrotik';

hasFirewallLogging('add chain=input action=drop log=yes');  // true
```

---

#### getLogPrefix

Get log prefix from a firewall rule.

**Signature:**
```typescript
function getLogPrefix(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The log prefix value.

**Example:**
```typescript
import { getLogPrefix } from '@sentriflow/core/helpers/mikrotik';

getLogPrefix('add chain=input action=drop log=yes log-prefix="DROPPED: "');
// Returns: 'DROPPED: '
```

---

#### getAddressList

Get address list name from a rule.

**Signature:**
```typescript
function getAddressList(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The address list name.

---

#### getSrcAddressList

Get source address list from a rule.

**Signature:**
```typescript
function getSrcAddressList(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The source address list name.

---

#### getDstAddressList

Get destination address list from a rule.

**Signature:**
```typescript
function getDstAddressList(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The destination address list name.

---

#### getConnectionLimit

Get connection limit from a rule.

**Signature:**
```typescript
function getConnectionLimit(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The connection limit value.

---

#### getRateLimit

Get rate limit from a rule.

**Signature:**
```typescript
function getRateLimit(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The limit value.

---

#### getTcpFlags

Get TCP flags from a firewall rule.

**Signature:**
```typescript
function getTcpFlags(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The TCP flags value.

---

#### getDstPort

Get destination port from a rule.

**Signature:**
```typescript
function getDstPort(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The destination port value.

---

#### getProtocol

Get protocol from a rule.

**Signature:**
```typescript
function getProtocol(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The protocol value (e.g., `tcp`, `udp`, `icmp`).

---

### 8. NAT Helpers

Functions for analyzing NAT configuration.

---

#### getNatAction

Get NAT action from a NAT rule.

**Signature:**
```typescript
function getNatAction(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The action (e.g., `masquerade`, `src-nat`, `dst-nat`).

**Example:**
```typescript
import { getNatAction } from '@sentriflow/core/helpers/mikrotik';

getNatAction('add chain=srcnat out-interface=WAN action=masquerade');  // 'masquerade'
```

---

### 9. Service Management

Functions for analyzing service configuration.

---

#### getServicePort

Get service port from `/ip service` command.

**Signature:**
```typescript
function getServicePort(nodeOrCommand: ConfigNode | string): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `number | undefined` - The port number or `undefined`.

**Example:**
```typescript
import { getServicePort } from '@sentriflow/core/helpers/mikrotik';

getServicePort('set ssh port=2222');  // 2222
```

---

#### isServiceDisabled

Check if a service is disabled.

**Signature:**
```typescript
function isServiceDisabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `disabled=yes`.

**Example:**
```typescript
import { isServiceDisabled } from '@sentriflow/core/helpers/mikrotik';

isServiceDisabled('set telnet disabled=yes');  // true
isServiceDisabled('set ssh disabled=no');       // false
```

---

### 10. System Configuration

Functions for analyzing system-level configuration.

---

#### getSystemIdentity

Get the system identity (hostname) from a `/system identity` block.

**Signature:**
```typescript
function getSystemIdentity(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The system identity node |

**Returns:** `string | undefined` - The system name or `undefined`.

**Example:**
```typescript
import { getSystemIdentity, findPathBlock } from '@sentriflow/core/helpers/mikrotik';

const identityBlock = findPathBlock(root, '/system identity');
const hostname = getSystemIdentity(identityBlock);  // e.g., 'Core-Router-01'
```

---

#### getSystemNote

Get system note content.

**Signature:**
```typescript
function getSystemNote(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The note content.

---

#### isNoteShowAtLogin

Check if system note is shown at login.

**Signature:**
```typescript
function isNoteShowAtLogin(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `show-at-login=yes`.

---

### 11. NTP Configuration

Functions for analyzing NTP settings.

---

#### isNtpEnabled

Check if NTP client is enabled.

**Signature:**
```typescript
function isNtpEnabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `enabled=yes`.

**Example:**
```typescript
import { isNtpEnabled } from '@sentriflow/core/helpers/mikrotik';

isNtpEnabled('set enabled=yes');  // true
```

---

#### getNtpServers

Get NTP servers from `/system ntp client servers` block.

**Signature:**
```typescript
function getNtpServers(ntpNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ntpNode | `ConfigNode` | The NTP servers section node |

**Returns:** `string[]` - Array of NTP server addresses.

**Example:**
```typescript
import { getNtpServers, findPathBlock } from '@sentriflow/core/helpers/mikrotik';

const ntpServers = findPathBlock(root, '/system ntp client servers');
const servers = getNtpServers(ntpServers);  // ['time.google.com', 'pool.ntp.org']
```

---

### 12. SSH Configuration

Functions for analyzing SSH security settings.

---

#### isSshStrongCrypto

Check if SSH strong-crypto is enabled.

**Signature:**
```typescript
function isSshStrongCrypto(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `strong-crypto=yes`.

**Example:**
```typescript
import { isSshStrongCrypto } from '@sentriflow/core/helpers/mikrotik';

isSshStrongCrypto('set strong-crypto=yes host-key-type=ed25519');  // true
```

---

#### getSshHostKeyType

Get SSH host key type.

**Signature:**
```typescript
function getSshHostKeyType(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The host key type (e.g., `rsa`, `ed25519`).

**Example:**
```typescript
import { getSshHostKeyType } from '@sentriflow/core/helpers/mikrotik';

getSshHostKeyType('set host-key-type=ed25519');  // 'ed25519'
```

---

### 13. SNMP Configuration

Functions for analyzing SNMP security settings.

---

#### getSnmpSecurity

Get SNMP community security level.

**Signature:**
```typescript
function getSnmpSecurity(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The security level (e.g., `none`, `authorized`, `private`).

---

#### getSnmpCommunityName

Get SNMP community name.

**Signature:**
```typescript
function getSnmpCommunityName(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The community name.

---

#### hasSnmpAuthProtocol

Check if SNMP has authentication protocol configured.

**Signature:**
```typescript
function hasSnmpAuthProtocol(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `authentication-protocol=` is present.

---

#### hasSnmpEncryptionProtocol

Check if SNMP has encryption protocol configured.

**Signature:**
```typescript
function hasSnmpEncryptionProtocol(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `encryption-protocol=` is present.

---

### 14. Interface Lists and Discovery

Functions for analyzing interface list and neighbor discovery settings.

---

#### getAllowedInterfaceList

Get allowed interface list property.

**Signature:**
```typescript
function getAllowedInterfaceList(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The allowed interface list name.

---

#### getDiscoverInterfaceList

Get discover interface list from neighbor discovery settings.

**Signature:**
```typescript
function getDiscoverInterfaceList(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The discover interface list name.

---

#### isMacPingEnabled

Check if MAC-Ping is enabled.

**Signature:**
```typescript
function isMacPingEnabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if enabled (default is enabled if not explicitly disabled).

**Note:** Returns `true` unless `enabled=no` is explicitly set.

---

### 15. BGP Configuration

Functions for analyzing BGP routing security.

---

#### getBgpTcpMd5Key

Get BGP TCP-MD5 key (checks if authentication is configured).

**Signature:**
```typescript
function getBgpTcpMd5Key(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The TCP-MD5 key or `undefined`.

**Example:**
```typescript
import { getBgpTcpMd5Key } from '@sentriflow/core/helpers/mikrotik';

const key = getBgpTcpMd5Key('add name=peer1 remote.as=65001 tcp-md5-key=secret123');
// Returns: 'secret123'
```

---

#### getBgpRemoteAs

Get BGP remote AS number. Supports both RouterOS 6 (`remote-as`) and RouterOS 7 (`remote.as`) syntax.

**Signature:**
```typescript
function getBgpRemoteAs(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The remote AS number.

**Example:**
```typescript
import { getBgpRemoteAs } from '@sentriflow/core/helpers/mikrotik';

// RouterOS 7
getBgpRemoteAs('add name=peer1 remote.as=65001');  // '65001'

// RouterOS 6
getBgpRemoteAs('add remote-address=10.0.0.1 remote-as=65001');  // '65001'
```

---

#### getBgpMaxPrefixLimit

Get BGP max prefix limit. Supports both RouterOS 6 and 7 syntax.

**Signature:**
```typescript
function getBgpMaxPrefixLimit(nodeOrCommand: ConfigNode | string): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `number | undefined` - The maximum prefix limit or `undefined`.

---

#### hasBgpInputFilter

Check if BGP has input filter configured. Supports both RouterOS 6 (`in-filter`) and RouterOS 7 (`input.filter`).

**Signature:**
```typescript
function hasBgpInputFilter(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if input filter is configured.

---

#### hasBgpOutputFilter

Check if BGP has output filter configured. Supports both RouterOS 6 (`out-filter`) and RouterOS 7 (`output.filter`).

**Signature:**
```typescript
function hasBgpOutputFilter(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if output filter is configured.

---

### 16. OSPF Configuration

Functions for analyzing OSPF routing security.

---

#### getOspfAuth

Get OSPF authentication type.

**Signature:**
```typescript
function getOspfAuth(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The authentication type (e.g., `simple`, `md5`).

---

#### getOspfAuthKey

Get OSPF authentication key.

**Signature:**
```typescript
function getOspfAuthKey(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The authentication key.

**Note:** Checks both `auth-key` and `authentication-key` properties.

---

### 17. VRRP Configuration

Functions for analyzing VRRP settings.

---

#### getVrrpAuth

Get VRRP authentication type.

**Signature:**
```typescript
function getVrrpAuth(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The authentication type.

---

#### getVrrpPassword

Get VRRP password.

**Signature:**
```typescript
function getVrrpPassword(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The password.

---

### 18. IPsec Configuration

Functions for analyzing IPsec security settings.

---

#### getIpsecEncAlgorithm

Get IPsec encryption algorithm.

**Signature:**
```typescript
function getIpsecEncAlgorithm(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The encryption algorithm(s).

**Note:** Checks both `enc-algorithm` and `enc-algorithms` properties.

---

#### getIpsecHashAlgorithm

Get IPsec hash/authentication algorithm.

**Signature:**
```typescript
function getIpsecHashAlgorithm(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The hash algorithm(s).

**Note:** Checks both `hash-algorithm` and `auth-algorithms` properties.

---

#### getIpsecDhGroup

Get IPsec Diffie-Hellman group.

**Signature:**
```typescript
function getIpsecDhGroup(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The DH group.

**Note:** Checks both `dh-group` and `pfs-group` properties.

---

### 19. Bridge Configuration

Functions for analyzing bridge settings.

---

#### hasBridgeVlanFiltering

Check if bridge has VLAN filtering enabled.

**Signature:**
```typescript
function hasBridgeVlanFiltering(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `vlan-filtering=yes`.

**Example:**
```typescript
import { hasBridgeVlanFiltering } from '@sentriflow/core/helpers/mikrotik';

hasBridgeVlanFiltering('add name=bridge1 vlan-filtering=yes');  // true
```

---

#### getBridgeFrameTypes

Get bridge frame types.

**Signature:**
```typescript
function getBridgeFrameTypes(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The frame types value.

---

### 20. Logging Configuration

Functions for analyzing syslog/logging settings.

---

#### getSyslogTarget

Get syslog target type.

**Signature:**
```typescript
function getSyslogTarget(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The target type (e.g., `remote`, `disk`, `memory`).

---

#### getSyslogRemote

Get syslog remote address.

**Signature:**
```typescript
function getSyslogRemote(nodeOrCommand: ConfigNode | string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `string | undefined` - The remote syslog server address.

---

### 21. Miscellaneous Services

Functions for analyzing various service settings.

---

#### isCloudDdnsEnabled

Check if IP cloud DDNS is enabled.

**Signature:**
```typescript
function isCloudDdnsEnabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `ddns-enabled=yes`.

---

#### isProxyEnabled

Check if IP proxy is enabled.

**Signature:**
```typescript
function isProxyEnabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `enabled=yes`.

---

#### isSocksEnabled

Check if IP SOCKS is enabled.

**Signature:**
```typescript
function isSocksEnabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `enabled=yes`.

---

#### isUpnpEnabled

Check if UPnP is enabled.

**Signature:**
```typescript
function isUpnpEnabled(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `enabled=yes`.

---

#### isDnsAllowRemoteRequests

Check if DNS allows remote requests.

**Signature:**
```typescript
function isDnsAllowRemoteRequests(nodeOrCommand: ConfigNode | string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeOrCommand | `ConfigNode \| string` | The node or command string |

**Returns:** `boolean` - `true` if `allow-remote-requests=yes`.

**Security Note:** Allowing remote DNS requests can expose the router to DNS amplification attacks if not properly secured with firewall rules.

**Example:**
```typescript
import { isDnsAllowRemoteRequests } from '@sentriflow/core/helpers/mikrotik';

isDnsAllowRemoteRequests('set allow-remote-requests=yes servers=8.8.8.8');  // true
```

---

## See Also

- [Helper Functions Overview](./README.md)
- [Common Helpers](./common.md) - Shared helpers for IP parsing, subnet calculations, etc.
- [Cisco Helpers](./cisco.md) - Similar helpers for Cisco IOS/IOS-XE
- [Juniper Helpers](./juniper.md) - Similar helpers for Junos
- [Fortinet Helpers](./fortinet.md) - Similar helpers for FortiOS
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - How to create validation rules using these helpers

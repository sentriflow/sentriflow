// packages/core/test/parser-vendors.test.ts

import { describe, test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  SchemaAwareParser,
  detectVendor,
  getVendor,
  isValidVendor,
  getAvailableVendors,
  CiscoIOSSchema,
  CiscoNXOSSchema,
  JuniperJunOSSchema,
  PaloAltoPANOSSchema,
  AristaEOSSchema,
  ExtremeEXOSSchema,
  ExtremeVOSSSchema,
  HuaweiVRPSchema,
} from '../src';

// ============ Vendor Detection Tests ============

describe('Vendor Detection', () => {
  test('should detect Cisco IOS from interface config', () => {
    const config = `interface GigabitEthernet0/1
 description Uplink
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/2
 description Server Link
 switchport mode access
 switchport access vlan 10
!`;
    expect(detectVendor(config).id).toBe('cisco-ios');
  });

  test('should detect Cisco IOS from router config', () => {
    const config = `router bgp 65000
 bgp router-id 192.168.1.1
 neighbor 10.0.0.2 remote-as 65001
 address-family ipv4 unicast
  neighbor 10.0.0.2 activate
 exit-address-family
!`;
    expect(detectVendor(config).id).toBe('cisco-ios');
  });

  test('should detect Cisco NX-OS from feature commands', () => {
    const config = `feature bgp
feature ospf
feature vpc
feature lacp
!
interface Ethernet1/1
 description To Spine
 no switchport
 ip address 10.0.0.1/30
 no shutdown`;
    expect(detectVendor(config).id).toBe('cisco-nxos');
  });

  test('should detect Cisco NX-OS from vdc command', () => {
    const config = `vdc nx9k-1 id 1
 limit-resource vlan minimum 16 maximum 4094
 limit-resource vrf minimum 2 maximum 4096
!
feature bgp`;
    expect(detectVendor(config).id).toBe('cisco-nxos');
  });

  test('should detect Cisco NX-OS from vrf context', () => {
    const config = `vrf context management
 ip route 0.0.0.0/0 10.0.0.1
!
interface mgmt0
 vrf member management
 ip address 10.0.0.100/24`;
    expect(detectVendor(config).id).toBe('cisco-nxos');
  });

  test('should detect Cisco NX-OS from vpc domain', () => {
    const config = `vpc domain 100
 peer-switch
 peer-keepalive destination 10.0.0.2
 peer-gateway
 ip arp synchronize`;
    expect(detectVendor(config).id).toBe('cisco-nxos');
  });

  test('should detect Juniper JunOS from hierarchical braces', () => {
    const config = `system {
    host-name router1;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}`;
    expect(detectVendor(config).id).toBe('juniper-junos');
  });

  test('should detect Juniper JunOS from set commands', () => {
    const config = `set system host-name router1
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set protocols bgp group IBGP type internal
set protocols bgp group IBGP neighbor 192.168.1.2`;
    expect(detectVendor(config).id).toBe('juniper-junos');
  });

  test('should detect Juniper JunOS from protocols stanza', () => {
    const config = `protocols {
    bgp {
        group IBGP {
            type internal;
            neighbor 192.168.1.2;
        }
    }
}`;
    expect(detectVendor(config).id).toBe('juniper-junos');
  });

  test('should default to Cisco IOS for unknown format', () => {
    const config = `hostname unknown-device
some random command
another command`;
    expect(detectVendor(config).id).toBe('cisco-ios');
  });

  test('should detect Palo Alto PAN-OS from deviceconfig', () => {
    const config = `deviceconfig {
    system {
        hostname firewall-01;
        ip-address 192.168.1.1;
    }
}`;
    expect(detectVendor(config).id).toBe('paloalto-panos');
  });

  test('should detect Palo Alto PAN-OS from rulebase', () => {
    const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                action allow;
            }
        }
    }
}`;
    expect(detectVendor(config).id).toBe('paloalto-panos');
  });

  test('should detect Palo Alto PAN-OS from set commands', () => {
    const config = `set deviceconfig system hostname pa-fw-01
set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24
set zone trust network layer3 ethernet1/2
set rulebase security rules allow-outbound from trust`;
    expect(detectVendor(config).id).toBe('paloalto-panos');
  });

  test('should detect Palo Alto PAN-OS from Panorama config', () => {
    const config = `device-group {
    enterprise-firewalls {
        pre-rulebase {
            security {
                rules {
                    global-deny {
                        action deny;
                    }
                }
            }
        }
    }
}`;
    expect(detectVendor(config).id).toBe('paloalto-panos');
  });

  test('should detect Palo Alto PAN-OS from GlobalProtect', () => {
    const config = `global-protect {
    global-protect-gateway {
        gateway-name {
            local-address {
                interface ethernet1/1;
            }
        }
    }
}`;
    expect(detectVendor(config).id).toBe('paloalto-panos');
  });

  // ============ Arista EOS Detection Tests ============

  test('should detect Arista EOS from MLAG configuration', () => {
    const config = `hostname arista-leaf-01
!
mlag configuration
   domain-id MLAG_DOMAIN
   local-interface Vlan4094
   peer-address 10.255.255.2
   peer-link Port-Channel1
!`;
    expect(detectVendor(config).id).toBe('arista-eos');
  });

  test('should detect Arista EOS from management api http-commands', () => {
    const config = `hostname arista-switch
!
management api http-commands
   protocol https
   no shutdown
!`;
    expect(detectVendor(config).id).toBe('arista-eos');
  });

  test('should detect Arista EOS from daemon configuration', () => {
    const config = `hostname arista-switch
!
daemon TerminAttr
   exec /usr/bin/TerminAttr -cvaddr=10.0.0.1:9910
   no shutdown
!`;
    expect(detectVendor(config).id).toBe('arista-eos');
  });

  test('should detect Arista EOS from event-handler', () => {
    const config = `hostname arista-switch
!
event-handler BACKUP_CONFIG
   trigger on-startup-config
   action bash /mnt/flash/backup.sh
!`;
    expect(detectVendor(config).id).toBe('arista-eos');
  });

  test('should detect Arista EOS from vrf instance syntax', () => {
    const config = `hostname arista-switch
!
vrf instance MGMT
   description Management VRF
!
interface Management1
   vrf MGMT
   ip address 10.0.0.1/24
!`;
    expect(detectVendor(config).id).toBe('arista-eos');
  });

  test('should detect Arista EOS from interface Vxlan', () => {
    const config = `hostname arista-vxlan-leaf
!
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vni 10010 vlan 10
!`;
    expect(detectVendor(config).id).toBe('arista-eos');
  });

  test('should detect Arista EOS from peer-filter', () => {
    const config = `hostname arista-spine
!
peer-filter LEAF_AS_RANGE
   10 match as-range 65001-65100 result accept
!`;
    expect(detectVendor(config).id).toBe('arista-eos');
  });
});

// ============ Vendor Registry Tests ============

describe('Vendor Registry', () => {
  test('should get vendor by ID', () => {
    expect(getVendor('cisco-ios')).toBe(CiscoIOSSchema);
    expect(getVendor('cisco-nxos')).toBe(CiscoNXOSSchema);
    expect(getVendor('juniper-junos')).toBe(JuniperJunOSSchema);
    expect(getVendor('paloalto-panos')).toBe(PaloAltoPANOSSchema);
    expect(getVendor('arista-eos')).toBe(AristaEOSSchema);
  });

  test('should throw for unknown vendor', () => {
    expect(() => getVendor('unknown-vendor')).toThrow('Unknown vendor');
  });

  test('should validate vendor IDs', () => {
    expect(isValidVendor('cisco-ios')).toBe(true);
    expect(isValidVendor('cisco-nxos')).toBe(true);
    expect(isValidVendor('juniper-junos')).toBe(true);
    expect(isValidVendor('paloalto-panos')).toBe(true);
    expect(isValidVendor('arista-eos')).toBe(true);
    expect(isValidVendor('unknown')).toBe(false);
  });

  test('should list available vendors', () => {
    const vendors = getAvailableVendors();
    expect(vendors).toContain('cisco-ios');
    expect(vendors).toContain('cisco-nxos');
    expect(vendors).toContain('juniper-junos');
    expect(vendors).toContain('paloalto-panos');
    expect(vendors).toContain('arista-eos');
  });
});

// ============ Cisco IOS Parsing Tests ============

describe('Cisco IOS Parser', () => {
  test('should parse basic interface config', () => {
    const config = `interface GigabitEthernet0/1
 description Uplink
 ip address 10.0.0.1 255.255.255.0
 no shutdown`;

    const parser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^interface GigabitEthernet0\/1/i);
    expect(ast[0]?.children).toHaveLength(3);
  });

  test('should parse nested address-family', () => {
    const config = `router bgp 65000
 bgp router-id 192.168.1.1
 address-family ipv4 unicast
  neighbor 10.0.0.2 activate
 exit-address-family`;

    const parser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');

    // Find address-family within router bgp
    const routerBgp = ast[0];
    const addressFamily = routerBgp?.children.find(
      (c) => c.id.match(/^address-family/i)
    );
    expect(addressFamily).toBeDefined();
    expect(addressFamily?.type).toBe('section');
    expect(addressFamily?.blockDepth).toBe(1);
  });

  test('should handle comments', () => {
    const config = `! This is a comment
interface Loopback0
 ! Another comment
 ip address 192.168.1.1 255.255.255.255`;

    const parser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    const ast = parser.parse(config);

    // Comments should be skipped
    expect(ast).toHaveLength(1);
    expect(ast[0]?.children).toHaveLength(1);
  });
});

// ============ Cisco NX-OS Parsing Tests ============

describe('Cisco NX-OS Parser', () => {
  test('should parse feature commands as top-level', () => {
    const config = `feature bgp
feature ospf
feature vpc`;

    const parser = new SchemaAwareParser({ vendor: CiscoNXOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(3);
    ast.forEach((node) => {
      expect(node.type).toBe('section');
      expect(node.id).toMatch(/^feature/i);
    });
  });

  test('should parse vpc domain config', () => {
    const config = `vpc domain 100
 peer-switch
 peer-keepalive destination 10.0.0.2
 peer-gateway`;

    const parser = new SchemaAwareParser({ vendor: CiscoNXOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.children).toHaveLength(3);
  });
});

// ============ Juniper JunOS Parsing Tests ============

describe('Juniper JunOS Parser', () => {
  test('should parse basic hierarchical config', () => {
    const config = `system {
    host-name router1;
}`;

    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toBe('system');
    expect(ast[0]?.children).toHaveLength(1);
    expect(ast[0]?.children[0]?.id).toBe('host-name router1');
  });

  test('should parse nested interface config', () => {
    const config = `interfaces {
    ge-0/0/0 {
        description "Uplink";
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}`;

    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toBe('interfaces');

    // Check nested structure
    const interfaces = ast[0];
    expect(interfaces?.children).toHaveLength(1);

    const ge000 = interfaces?.children[0];
    expect(ge000?.id).toBe('ge-0/0/0');
    expect(ge000?.type).toBe('section');
  });

  test('should parse BGP config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/juniper-junos/bgp-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    // Should have routing-options, protocols, and policy-options
    const topLevelIds = ast.map((n) => n.id);
    expect(topLevelIds).toContain('routing-options');
    expect(topLevelIds).toContain('protocols');
    expect(topLevelIds).toContain('policy-options');
  });

  test('should parse firewall filter from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/juniper-junos/firewall-filter.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.id).toBe('firewall');
    expect(ast[0]?.type).toBe('section');
  });

  test('should handle JunOS comments', () => {
    const config = `# This is a comment
system {
    # Another comment
    host-name router1;
}`;

    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.id).toBe('system');
    expect(ast[0]?.children).toHaveLength(1);
  });

  test('should handle inline braces', () => {
    const config = `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }`;

    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    // Due to inline format, parsing may vary, but should not crash
    expect(ast.length).toBeGreaterThan(0);
  });
});

// ============ Parser getVendor() Method Tests ============

describe('Parser getVendor()', () => {
  test('should return the vendor used by parser', () => {
    const ciscoParser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    expect(ciscoParser.getVendor()).toBe(CiscoIOSSchema);

    const juniperParser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    expect(juniperParser.getVendor()).toBe(JuniperJunOSSchema);
  });

  test('should default to Cisco IOS', () => {
    const defaultParser = new SchemaAwareParser();
    expect(defaultParser.getVendor().id).toBe('cisco-ios');
  });
});

// ============ VendorSchema Interface Tests ============

describe('VendorSchema Interface', () => {
  test('Cisco IOS schema has expected properties', () => {
    expect(CiscoIOSSchema.id).toBe('cisco-ios');
    expect(CiscoIOSSchema.name).toBe('Cisco IOS/IOS-XE');
    expect(CiscoIOSSchema.useBraceHierarchy).toBe(false);
    expect(CiscoIOSSchema.blockStarters.length).toBeGreaterThan(0);
    expect(CiscoIOSSchema.blockEnders.length).toBeGreaterThan(0);
    expect(CiscoIOSSchema.commentPatterns.length).toBeGreaterThan(0);
  });

  test('Cisco NX-OS schema has expected properties', () => {
    expect(CiscoNXOSSchema.id).toBe('cisco-nxos');
    expect(CiscoNXOSSchema.name).toBe('Cisco NX-OS');
    expect(CiscoNXOSSchema.useBraceHierarchy).toBe(false);
  });

  test('Juniper JunOS schema has expected properties', () => {
    expect(JuniperJunOSSchema.id).toBe('juniper-junos');
    expect(JuniperJunOSSchema.name).toBe('Juniper JunOS');
    expect(JuniperJunOSSchema.useBraceHierarchy).toBe(true);
    expect(JuniperJunOSSchema.sectionDelimiter).toBe('}');
  });

  test('Palo Alto PAN-OS schema has expected properties', () => {
    expect(PaloAltoPANOSSchema.id).toBe('paloalto-panos');
    expect(PaloAltoPANOSSchema.name).toBe('Palo Alto PAN-OS');
    expect(PaloAltoPANOSSchema.useBraceHierarchy).toBe(true);
    expect(PaloAltoPANOSSchema.sectionDelimiter).toBe('}');
    expect(PaloAltoPANOSSchema.blockStarters.length).toBeGreaterThan(0);
    expect(PaloAltoPANOSSchema.blockEnders.length).toBeGreaterThan(0);
    expect(PaloAltoPANOSSchema.commentPatterns.length).toBeGreaterThan(0);
  });

  test('Arista EOS schema has expected properties', () => {
    expect(AristaEOSSchema.id).toBe('arista-eos');
    expect(AristaEOSSchema.name).toBe('Arista EOS');
    expect(AristaEOSSchema.useBraceHierarchy).toBe(false);
    expect(AristaEOSSchema.sectionDelimiter).toBe('!');
    expect(AristaEOSSchema.blockStarters.length).toBeGreaterThan(0);
    expect(AristaEOSSchema.blockEnders.length).toBeGreaterThan(0);
    expect(AristaEOSSchema.commentPatterns.length).toBeGreaterThan(0);
  });
});

// ============ Palo Alto PAN-OS Parsing Tests ============

describe('Palo Alto PAN-OS Parser', () => {
  test('should parse basic deviceconfig', () => {
    const config = `deviceconfig {
    system {
        hostname firewall-01;
        ip-address 192.168.1.1;
    }
}`;

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toBe('deviceconfig');
    expect(ast[0]?.children).toHaveLength(1);
    expect(ast[0]?.children[0]?.id).toBe('system');
  });

  test('should parse nested security rules', () => {
    const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                source any;
                destination any;
                application web-browsing;
                action allow;
            }
        }
    }
}`;

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toBe('rulebase');

    // Check nested structure
    const security = ast[0]?.children.find((c) => c.id === 'security');
    expect(security).toBeDefined();
    expect(security?.type).toBe('section');
  });

  test('should parse network interfaces', () => {
    const config = `network {
    interface {
        ethernet {
            ethernet1/1 {
                layer3 {
                    ip {
                        10.0.0.1/24;
                    }
                }
            }
        }
    }
}`;

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.id).toBe('network');
    expect(ast[0]?.type).toBe('section');
  });

  test('should parse zone configuration', () => {
    const config = `zone {
    trust {
        network {
            layer3 ethernet1/2;
        }
        zone-protection-profile strict-protection;
    }
    untrust {
        network {
            layer3 ethernet1/1;
        }
    }
}`;

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.id).toBe('zone');
    expect(ast[0]?.children.length).toBeGreaterThan(0);
  });

  test('should parse profiles config', () => {
    const config = `profiles {
    virus {
        strict-av {
            decoder {
                ftp {
                    action reset-both;
                }
            }
        }
    }
    spyware {
        strict-spyware {
            botnet-domains {
                lists {
                    default-paloalto-dns;
                }
            }
        }
    }
}`;

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.id).toBe('profiles');
    expect(ast[0]?.type).toBe('section');

    const virus = ast[0]?.children.find((c) => c.id === 'virus');
    expect(virus).toBeDefined();
  });

  test('should handle PAN-OS comments', () => {
    const config = `# This is a comment
deviceconfig {
    # Another comment
    system {
        hostname firewall-01;
    }
}`;

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.id).toBe('deviceconfig');
  });

  test('should parse config from fixture file', () => {
    const fixturePath = join(__dirname, 'fixtures/paloalto-panos/basic-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const deviceconfig = ast.find((n) => n.id === 'deviceconfig');
    expect(deviceconfig).toBeDefined();
  });

  test('should parse security policy from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/paloalto-panos/security-policy.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const rulebase = ast.find((n) => n.id === 'rulebase');
    expect(rulebase).toBeDefined();
  });

  test('should parse network config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/paloalto-panos/network-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    const topLevelIds = ast.map((n) => n.id);
    expect(topLevelIds).toContain('network');
    expect(topLevelIds).toContain('zone');
  });

  test('should parse Panorama config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/paloalto-panos/panorama-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
    const ast = parser.parse(config);

    const topLevelIds = ast.map((n) => n.id);
    expect(topLevelIds).toContain('device-group');
    expect(topLevelIds).toContain('template');
    expect(topLevelIds).toContain('shared');
  });
});

// ============ Arista EOS Parsing Tests ============

describe('Arista EOS Parser', () => {
  test('should parse basic interface config', () => {
    const config = `interface Ethernet1
   description Uplink to Spine
   mtu 9214
   no switchport
   ip address 10.0.0.1/30`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^interface Ethernet1/i);
    expect(ast[0]?.children.length).toBeGreaterThan(0);
  });

  test('should parse MLAG configuration', () => {
    const config = `mlag configuration
   domain-id MLAG_DOMAIN
   local-interface Vlan4094
   peer-address 10.255.255.2
   peer-link Port-Channel1`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^mlag configuration/i);
    expect(ast[0]?.children).toHaveLength(4);
  });

  test('should parse VXLAN interface config', () => {
    const config = `interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vni 10010 vlan 10
   vxlan vni 10020 vlan 20`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^interface Vxlan1/i);
    expect(ast[0]?.children.length).toBeGreaterThan(0);
  });

  test('should parse management api config', () => {
    const config = `management api http-commands
   protocol https
   no shutdown`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^management api/i);
    expect(ast[0]?.children).toHaveLength(2);
  });

  test('should parse VRF instance', () => {
    const config = `vrf instance MGMT
   description Management VRF
!
vrf instance TENANT_A
   description Tenant A Production`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(2);
    expect(ast[0]?.id).toMatch(/^vrf instance MGMT/i);
    expect(ast[1]?.id).toMatch(/^vrf instance TENANT_A/i);
  });

  test('should parse router bgp with EVPN', () => {
    const config = `router bgp 65001
   router-id 192.168.255.1
   no bgp default ipv4-unicast
   neighbor SPINE peer group
   neighbor SPINE remote-as 65000
   address-family evpn
      neighbor SPINE activate
   address-family ipv4
      neighbor SPINE activate`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^router bgp 65001/i);

    // Find EVPN address-family
    const evpnAf = ast[0]?.children.find((c) => c.id.match(/^address-family evpn/i));
    expect(evpnAf).toBeDefined();
  });

  test('should handle Arista comments', () => {
    const config = `! This is a comment
hostname arista-leaf-01
! Another comment
interface Ethernet1
   ! Interface comment
   description Uplink`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    // Comments should be skipped, expect hostname and interface
    expect(ast.length).toBeGreaterThan(0);
  });

  test('should parse daemon configuration', () => {
    const config = `daemon TerminAttr
   exec /usr/bin/TerminAttr -cvaddr=10.0.0.1:9910
   no shutdown`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^daemon TerminAttr/i);
  });

  test('should parse event-handler', () => {
    const config = `event-handler BACKUP_CONFIG
   trigger on-startup-config
   action bash /mnt/flash/backup.sh`;

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^event-handler/i);
  });

  test('should parse basic config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/arista-eos/basic-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Should have hostname, interfaces, etc.
    const hasInterfaces = ast.some((n) => n.id.toLowerCase().startsWith('interface'));
    expect(hasInterfaces).toBe(true);
  });

  test('should parse MLAG config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/arista-eos/mlag-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const mlagConfig = ast.find((n) => n.id.toLowerCase().includes('mlag configuration'));
    expect(mlagConfig).toBeDefined();
  });

  test('should parse VXLAN EVPN config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/arista-eos/vxlan-evpn.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const vxlanInterface = ast.find((n) => n.id.toLowerCase().startsWith('interface vxlan'));
    expect(vxlanInterface).toBeDefined();
    const routerBgp = ast.find((n) => n.id.toLowerCase().startsWith('router bgp'));
    expect(routerBgp).toBeDefined();
  });

  test('should parse eAPI config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/arista-eos/eapi-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const managementApi = ast.find((n) => n.id.toLowerCase().startsWith('management api'));
    expect(managementApi).toBeDefined();
    const daemon = ast.find((n) => n.id.toLowerCase().startsWith('daemon'));
    expect(daemon).toBeDefined();
  });
});

// ============ Extreme Networks EXOS Detection Tests ============

describe('Extreme EXOS Vendor Detection', () => {
  test('should detect Extreme EXOS from create vlan command', () => {
    const config = `# Extreme Networks ExtremeXOS Configuration
configure snmp sysname "exos-switch-01"
create vlan "Management" tag 10
create vlan "Data" tag 20
configure vlan Management ipaddress 10.0.10.1/24`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });

  test('should detect Extreme EXOS from configure vlan ipaddress', () => {
    const config = `configure vlan Management ipaddress 10.0.10.1/24
configure vlan Data add ports 1:1-1:24 untagged`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });

  test('should detect Extreme EXOS from configure snmp sysname', () => {
    const config = `configure snmp sysname "exos-switch-01"
configure sntp-client primary server 10.0.10.100 vr VR-Default`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });

  test('should detect Extreme EXOS from enable sharing (LAG)', () => {
    const config = `enable sharing 1:49 grouping 1:49-1:50 algorithm address-based L3_L4 lacp
enable sharing 1:51 grouping 1:51-1:52 algorithm address-based L3_L4`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });

  test('should detect Extreme EXOS from configure sntp-client', () => {
    const config = `configure sntp-client primary server 10.0.10.100 vr VR-Default
configure sntp-client secondary server 10.0.10.101 vr VR-Default
enable sntp-client`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });

  test('should detect Extreme EXOS from create eaps', () => {
    const config = `create eaps ring1
configure eaps ring1 add control vlan EAPS_CTRL
configure eaps ring1 mode master`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });

  test('should detect Extreme EXOS from enable stacking', () => {
    const config = `enable stacking
configure stacking node-address 00:04:96:xx:xx:xx priority 100`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });

  test('should detect Extreme EXOS from configure mlag peer', () => {
    const config = `create mlag peer mlag-peer
configure mlag peer mlag-peer ipaddress 10.255.255.2 vr VR-Default`;
    expect(detectVendor(config).id).toBe('extreme-exos');
  });
});

// ============ Extreme Networks VOSS Detection Tests ============

describe('Extreme VOSS Vendor Detection', () => {
  test('should detect Extreme VOSS from vlan create command', () => {
    const config = `! Extreme Networks VOSS Configuration
snmp-server name "vsp-switch-01"
vlan create 10 type port-mstprstp 0
vlan create 20 type port-mstprstp 0`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from vlan members command', () => {
    const config = `vlan members 10 1/1-1/12 portmember
vlan members 20 1/13-1/24 portmember`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from vlan i-sid command', () => {
    const config = `vlan i-sid 100 10100
vlan i-sid 200 10200`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from interface GigabitEthernet', () => {
    const config = `interface GigabitEthernet 1/1
   no shutdown
   default-vlan-id 10
exit`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from interface mlt', () => {
    const config = `interface mlt 1
   no shutdown
   lacp enable
exit`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from mlt configuration', () => {
    const config = `mlt 1 enable
mlt 1 name "Uplink-MLT"
mlt 1 member 1/49,1/50`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from spbm configuration', () => {
    const config = `spbm 1 b-vid 4051-4052 primary 4051
spbm 1 nick-name 1.00.01`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from dvr configuration', () => {
    const config = `dvr leaf
dvr domain-id 1`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });

  test('should detect Extreme VOSS from snmp-server name', () => {
    const config = `snmp-server name "vsp-switch-01"
logging host 10.0.10.200`;
    expect(detectVendor(config).id).toBe('extreme-voss');
  });
});

// ============ Extreme EXOS Parser Tests ============

describe('Extreme EXOS Parser', () => {
  test('should parse basic EXOS config', () => {
    const config = `# Extreme Networks ExtremeXOS Configuration
configure snmp sysname "exos-switch-01"
create vlan "Management" tag 10
create vlan "Data" tag 20
configure vlan Management ipaddress 10.0.10.1/24
enable ssh2`;

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Check that create vlan commands are parsed
    const createVlans = ast.filter((n) => n.id.toLowerCase().startsWith('create vlan'));
    expect(createVlans.length).toBe(2);
  });

  test('should parse EXOS LAG configuration', () => {
    const config = `enable sharing 1:49 grouping 1:49-1:50 algorithm address-based L3_L4 lacp
enable sharing 1:51 grouping 1:51-1:52 algorithm address-based L3_L4 lacp`;

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(2);
    expect(ast[0]?.id).toMatch(/^enable sharing/i);
  });

  test('should parse EXOS SNTP configuration', () => {
    const config = `configure sntp-client primary server 10.0.10.100 vr VR-Default
configure sntp-client secondary server 10.0.10.101 vr VR-Default
enable sntp-client`;

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const sntpClient = ast.find((n) => n.id.toLowerCase().includes('sntp-client'));
    expect(sntpClient).toBeDefined();
  });

  test('should handle EXOS comments', () => {
    const config = `# This is a comment
configure snmp sysname "test-switch"
# Another comment
create vlan "Data" tag 10`;

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    // Comments should be skipped
    expect(ast).toHaveLength(2);
  });

  test('should parse basic config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-exos/basic-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Should have create vlan commands
    const hasVlan = ast.some((n) => n.id.toLowerCase().includes('vlan'));
    expect(hasVlan).toBe(true);
  });

  test('should parse LAG config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-exos/lag-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasSharing = ast.some((n) => n.id.toLowerCase().includes('sharing'));
    expect(hasSharing).toBe(true);
  });

  test('should parse stacking config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-exos/stacking-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasStacking = ast.some((n) => n.id.toLowerCase().includes('stacking'));
    expect(hasStacking).toBe(true);
  });

  test('should parse EAPS config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-exos/eaps-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasEaps = ast.some((n) => n.id.toLowerCase().includes('eaps'));
    expect(hasEaps).toBe(true);
  });

  test('should parse MLAG config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-exos/mlag-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasMlag = ast.some((n) => n.id.toLowerCase().includes('mlag'));
    expect(hasMlag).toBe(true);
  });
});

// ============ Extreme VOSS Parser Tests ============

describe('Extreme VOSS Parser', () => {
  test('should parse basic VOSS config', () => {
    const config = `!
snmp-server name "vsp-switch-01"
!
vlan create 10 type port-mstprstp 0
vlan create 20 type port-mstprstp 0
!
interface GigabitEthernet 1/1
   no shutdown
   default-vlan-id 10
exit
!`;

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Should have vlan create commands
    const hasVlanCreate = ast.some((n) => n.id.toLowerCase().startsWith('vlan create'));
    expect(hasVlanCreate).toBe(true);
  });

  test('should parse VOSS interface config', () => {
    const config = `interface GigabitEthernet 1/1
   no shutdown
   default-vlan-id 10
exit

interface GigabitEthernet 1/2
   shutdown
exit`;

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Find the GigabitEthernet interfaces
    const ge11 = ast.find((n) => n.id.toLowerCase().includes('gigabitethernet 1/1'));
    const ge12 = ast.find((n) => n.id.toLowerCase().includes('gigabitethernet 1/2'));
    expect(ge11).toBeDefined();
    expect(ge12).toBeDefined();
  });

  test('should parse VOSS MLT configuration', () => {
    const config = `mlt 1 enable
mlt 1 name "Uplink-MLT"
mlt 1 member 1/49,1/50

interface mlt 1
   lacp enable
   lacp key 1
exit`;

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasMlt = ast.some((n) => n.id.toLowerCase().includes('mlt'));
    expect(hasMlt).toBe(true);
  });

  test('should parse VOSS ISIS/SPBM configuration', () => {
    const config = `router isis
   spbm 1
   spbm 1 b-vid 4051-4052 primary 4051
   no shutdown
exit`;

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Check that router isis is parsed
    const routerIsis = ast.find((n) => n.id.toLowerCase().startsWith('router isis'));
    expect(routerIsis).toBeDefined();
  });

  test('should handle VOSS comments', () => {
    const config = `! This is a comment
snmp-server name "vsp-switch-01"
! Another comment
vlan create 10 type port-mstprstp 0`;

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    // Comments should be skipped
    expect(ast.length).toBe(2);
  });

  test('should parse basic config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-voss/basic-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Should have vlan create commands
    const hasVlan = ast.some((n) => n.id.toLowerCase().includes('vlan'));
    expect(hasVlan).toBe(true);
  });

  test('should parse SPBM config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-voss/spbm-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasSpbm = ast.some((n) => n.id.toLowerCase().includes('spbm'));
    expect(hasSpbm).toBe(true);
  });

  test('should parse MLT config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-voss/mlt-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasMlt = ast.some((n) => n.id.toLowerCase().includes('mlt'));
    expect(hasMlt).toBe(true);
  });

  test('should parse DVR config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/extreme-voss/dvr-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    const hasDvr = ast.some((n) => n.id.toLowerCase().includes('dvr'));
    expect(hasDvr).toBe(true);
  });
});

// ============ Extreme Networks VendorSchema Interface Tests ============

describe('Extreme Networks VendorSchema Interface', () => {
  test('Extreme EXOS schema has expected properties', () => {
    expect(ExtremeEXOSSchema.id).toBe('extreme-exos');
    expect(ExtremeEXOSSchema.name).toBe('Extreme Networks EXOS');
    expect(ExtremeEXOSSchema.useBraceHierarchy).toBe(false);
    expect(ExtremeEXOSSchema.blockStarters.length).toBeGreaterThan(0);
    expect(ExtremeEXOSSchema.commentPatterns.length).toBeGreaterThan(0);
  });

  test('Extreme VOSS schema has expected properties', () => {
    expect(ExtremeVOSSSchema.id).toBe('extreme-voss');
    expect(ExtremeVOSSSchema.name).toBe('Extreme Networks VOSS');
    expect(ExtremeVOSSSchema.useBraceHierarchy).toBe(false);
    expect(ExtremeVOSSSchema.sectionDelimiter).toBe('!');
    expect(ExtremeVOSSSchema.blockStarters.length).toBeGreaterThan(0);
    expect(ExtremeVOSSSchema.blockEnders.length).toBeGreaterThan(0);
    expect(ExtremeVOSSSchema.commentPatterns.length).toBeGreaterThan(0);
  });
});

// ============ Extreme Networks Vendor Registry Tests ============

describe('Extreme Networks Vendor Registry', () => {
  test('should get Extreme vendors by ID', () => {
    expect(getVendor('extreme-exos')).toBe(ExtremeEXOSSchema);
    expect(getVendor('extreme-voss')).toBe(ExtremeVOSSSchema);
  });

  test('should validate Extreme vendor IDs', () => {
    expect(isValidVendor('extreme-exos')).toBe(true);
    expect(isValidVendor('extreme-voss')).toBe(true);
  });

  test('should list Extreme vendors in available vendors', () => {
    const vendors = getAvailableVendors();
    expect(vendors).toContain('extreme-exos');
    expect(vendors).toContain('extreme-voss');
  });
});

// ============ Huawei VRP Detection Tests ============

describe('Huawei VRP Vendor Detection', () => {
  test('should detect Huawei VRP from sysname command', () => {
    const config = `#
sysname SW-CORE-01
#
vlan batch 10 20 30
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from interface GigabitEthernet with space', () => {
    const config = `interface GigabitEthernet 0/0/1
 description Uplink to Core
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
 undo shutdown
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from Vlanif interface', () => {
    const config = `interface Vlanif10
 ip address 10.10.10.1 255.255.255.0
 description Management Interface
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from XGigabitEthernet', () => {
    const config = `interface XGigabitEthernet 0/0/1
 description 10G Uplink
 port link-type trunk
 undo shutdown
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from Eth-Trunk', () => {
    const config = `interface Eth-Trunk 1
 description LAG to Server
 port link-type trunk
 mode lacp-static
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from undo command', () => {
    const config = `#
undo info-center enable
undo shutdown
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from ospf command', () => {
    const config = `ospf 1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from bgp command', () => {
    const config = `bgp 65000
 router-id 1.1.1.1
 peer 2.2.2.2 as-number 65000
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from user-interface', () => {
    const config = `user-interface vty 0 4
 authentication-mode aaa
 protocol inbound ssh
 idle-timeout 15 0
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from local-user', () => {
    const config = `local-user admin password irreversible-cipher Admin@123
local-user admin privilege level 15
local-user admin service-type ssh
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from ip vpn-instance', () => {
    const config = `ip vpn-instance CUSTOMER-A
 ipv4-family
  route-distinguisher 65000:100
  vpn-target 65000:100 export-extcommunity
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from hwtacacs-server', () => {
    const config = `hwtacacs-server template TACACS-TEMPLATE
 hwtacacs-server authentication 10.10.10.60
 hwtacacs-server shared-key cipher TacacsSecret
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from info-center', () => {
    const config = `info-center enable
info-center loghost 10.10.10.200
info-center source default channel console debug state off
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from port link-type', () => {
    const config = `interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });

  test('should detect Huawei VRP from port default vlan', () => {
    const config = `interface GigabitEthernet0/0/2
 port link-type access
 port default vlan 20
#`;
    expect(detectVendor(config).id).toBe('huawei-vrp');
  });
});

// ============ Huawei VRP Parsing Tests ============

describe('Huawei VRP Parser', () => {
  test('should parse basic interface config', () => {
    const config = `interface GigabitEthernet 0/0/1
 description Uplink
 port link-type trunk
 port trunk allow-pass vlan 10 20
 undo shutdown
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^interface GigabitEthernet 0\/0\/1/i);
    expect(ast[0]?.children.length).toBeGreaterThanOrEqual(4);
  });

  test('should parse VLAN configuration', () => {
    const config = `vlan 10
 name Management
 description Management VLAN
#
vlan 20
 name Users
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThanOrEqual(2);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^vlan 10/i);
  });

  test('should parse OSPF configuration', () => {
    const config = `ospf 1 router-id 1.1.1.1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255
  network 1.1.1.1 0.0.0.0
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^ospf 1/i);
  });

  test('should parse BGP configuration', () => {
    const config = `bgp 65000
 router-id 1.1.1.1
 peer 2.2.2.2 as-number 65000
 ipv4-family unicast
  peer 2.2.2.2 enable
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^bgp 65000/i);
  });

  test('should parse AAA configuration', () => {
    const config = `aaa
 authentication-scheme default
 authorization-scheme default
 local-user admin password irreversible-cipher Admin@123
 local-user admin privilege level 15
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // AAA block should be present
    const aaaBlock = ast.find((n) => n.id === 'aaa');
    expect(aaaBlock).toBeDefined();
    expect(aaaBlock?.type).toBe('section');
    // Should have some children (authentication-scheme, authorization-scheme are nested blocks)
    expect(ast.length).toBeGreaterThanOrEqual(1);
  });

  test('should parse ACL configuration', () => {
    const config = `acl number 2000
 rule 5 permit source 10.10.10.0 0.0.0.255
 rule 10 permit source 10.20.20.0 0.0.0.255
 rule 100 deny
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    expect(ast).toHaveLength(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/^acl/i);
  });

  test('should parse user-interface configuration', () => {
    const config = `user-interface vty 0 4
 acl 2000 inbound
 authentication-mode aaa
 protocol inbound ssh
 idle-timeout 10 0
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // User-interface block should be present
    const vtyBlock = ast.find((n) => n.id.toLowerCase().startsWith('user-interface vty'));
    expect(vtyBlock).toBeDefined();
    expect(vtyBlock?.type).toBe('section');
    // Should have commands under user-interface
    expect(ast.length).toBeGreaterThanOrEqual(1);
  });

  test('should parse basic config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/huawei-vrp/basic-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // Should have multiple top-level sections
    expect(ast.length).toBeGreaterThan(5);

    // Find interfaces (Vlanif or GigabitEthernet)
    const interfaces = ast.filter((n) => n.id.toLowerCase().startsWith('interface'));
    expect(interfaces.length).toBeGreaterThan(0);

    // Find VLANs
    const vlans = ast.filter((n) => n.id.toLowerCase().startsWith('vlan'));
    expect(vlans.length).toBeGreaterThan(0);

    // Find AAA block
    const aaa = ast.find((n) => n.id === 'aaa');
    expect(aaa).toBeDefined();

    // Find user-interface blocks
    const userInterfaces = ast.filter((n) => n.id.toLowerCase().startsWith('user-interface'));
    expect(userInterfaces.length).toBeGreaterThan(0);
  });

  test('should parse BGP config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/huawei-vrp/bgp-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // Should have BGP block
    const bgp = ast.find((n) => n.id.toLowerCase().startsWith('bgp'));
    expect(bgp).toBeDefined();

    // Should have VPN instances
    const vpnInstances = ast.filter((n) => n.id.toLowerCase().includes('vpn-instance'));
    expect(vpnInstances.length).toBeGreaterThan(0);
  });

  test('should parse OSPF config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/huawei-vrp/ospf-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // Should have OSPF block
    const ospf = ast.find((n) => n.id.toLowerCase().startsWith('ospf'));
    expect(ospf).toBeDefined();
  });

  test('should parse security config from fixture', () => {
    const fixturePath = join(__dirname, 'fixtures/huawei-vrp/security-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // Should have ACL blocks
    const acls = ast.filter((n) => n.id.toLowerCase().startsWith('acl'));
    expect(acls.length).toBeGreaterThan(0);

    // Should have AAA block
    const aaa = ast.find((n) => n.id === 'aaa');
    expect(aaa).toBeDefined();

    // Should have user-interface blocks
    const userInterfaces = ast.filter((n) => n.id.toLowerCase().startsWith('user-interface'));
    expect(userInterfaces.length).toBeGreaterThan(0);
  });

  test('should handle Huawei comments', () => {
    const config = `# This is a header comment
#
sysname Router-01
#
interface GigabitEthernet 0/0/1
 description Test
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // Should parse without errors, comments should be handled
    expect(ast.length).toBeGreaterThan(0);
  });

  test('should parse VRRP commands as interface children (not top-level blocks)', () => {
    // VRRP commands should remain children of the interface, not become top-level blocks
    // This is critical for rules that check interface VRRP configuration
    const config = `interface Vlanif100
 ip address 10.1.1.2 255.255.255.0
 vrrp vrid 1 virtual-ip 10.1.1.1
 vrrp vrid 1 priority 110
 vrrp vrid 1 preempt-mode timer delay 60
 vrrp vrid 1 authentication-mode md5 key123
 undo shutdown
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // Should have exactly 1 top-level node (the interface)
    expect(ast).toHaveLength(1);
    expect(ast[0]?.id).toBe('interface Vlanif100');
    expect(ast[0]?.type).toBe('section');

    // All VRRP commands should be children of the interface
    const children = ast[0]?.children ?? [];
    expect(children.length).toBe(6); // ip address + 4 vrrp + undo shutdown

    // Verify VRRP commands are present as children
    const vrrpChildren = children.filter((c) => c.id.toLowerCase().startsWith('vrrp vrid'));
    expect(vrrpChildren.length).toBe(4);

    // Verify authentication is in children
    const authChild = children.find((c) => c.id.toLowerCase().includes('authentication-mode'));
    expect(authChild).toBeDefined();
    expect(authChild?.id).toContain('vrrp vrid 1 authentication-mode');
  });

  test('should parse multiple VRRP groups on same interface', () => {
    const config = `interface Vlanif100
 ip address 10.1.1.2 255.255.255.0
 vrrp vrid 1 virtual-ip 10.1.1.1
 vrrp vrid 1 priority 110
 vrrp vrid 2 virtual-ip 10.1.1.254
 vrrp vrid 2 priority 100
#`;

    const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
    const ast = parser.parse(config);

    // Should have exactly 1 top-level node (the interface)
    expect(ast).toHaveLength(1);

    // All VRRP commands for both VRIDs should be children
    const children = ast[0]?.children ?? [];
    const vrrpVrid1 = children.filter((c) => c.id.toLowerCase().includes('vrrp vrid 1'));
    const vrrpVrid2 = children.filter((c) => c.id.toLowerCase().includes('vrrp vrid 2'));

    expect(vrrpVrid1.length).toBe(2);
    expect(vrrpVrid2.length).toBe(2);
  });
});

// ============ Huawei VRP Schema Tests ============

describe('Huawei VRP Schema', () => {
  test('should have correct vendor ID', () => {
    expect(HuaweiVRPSchema.id).toBe('huawei-vrp');
  });

  test('should have display name', () => {
    expect(HuaweiVRPSchema.name).toBe('Huawei VRP');
  });

  test('should not use brace hierarchy', () => {
    expect(HuaweiVRPSchema.useBraceHierarchy).toBe(false);
  });

  test('should have # as section delimiter', () => {
    expect(HuaweiVRPSchema.sectionDelimiter).toBe('#');
  });

  test('should have block starters defined', () => {
    expect(HuaweiVRPSchema.blockStarters.length).toBeGreaterThan(0);
  });

  test('should have block enders defined', () => {
    expect(HuaweiVRPSchema.blockEnders.length).toBeGreaterThan(0);
    // Should include quit
    const hasQuit = HuaweiVRPSchema.blockEnders.some((re) => re.test('quit'));
    expect(hasQuit).toBe(true);
  });

  test('should have comment patterns defined', () => {
    expect(HuaweiVRPSchema.commentPatterns.length).toBeGreaterThan(0);
  });
});

// ============ Huawei VRP Vendor Registry Tests ============

describe('Huawei VRP Vendor Registry', () => {
  test('should get Huawei VRP by ID', () => {
    expect(getVendor('huawei-vrp')).toBe(HuaweiVRPSchema);
  });

  test('should validate Huawei VRP vendor ID', () => {
    expect(isValidVendor('huawei-vrp')).toBe(true);
  });

  test('should list Huawei VRP in available vendors', () => {
    const vendors = getAvailableVendors();
    expect(vendors).toContain('huawei-vrp');
  });
});

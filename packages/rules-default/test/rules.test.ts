import { describe, expect, test } from 'bun:test';
import { SchemaAwareParser, RuleEngine } from '@sentriflow/core';
import { NoMulticastBroadcastIp, OspfNetworkBestPractice, allRules } from '../src/index';
import { readFile } from 'fs/promises';
import { join } from 'path';

const fixturesDir = join(import.meta.dir, 'fixtures');

describe('IP Address Validation (NET-IP-001)', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();
    const ipRules = [NoMulticastBroadcastIp];

    test('valid-config.txt should pass IP validation', async () => {
        const configPath = join(fixturesDir, 'valid-config.txt');
        const config = await readFile(configPath, 'utf-8');

        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });

    test('valid-long.txt should pass IP validation', async () => {
        const configPath = join(fixturesDir, 'valid-long.txt');
        const config = await readFile(configPath, 'utf-8');

        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });

    test('invalid-ip.txt should detect multicast and broadcast violations', async () => {
        const configPath = join(fixturesDir, 'invalid-ip.txt');
        const config = await readFile(configPath, 'utf-8');

        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);

        // Expect 2 failures (one multicast, one broadcast)
        expect(failures).toHaveLength(2);

        // Verify specific error messages or IDs
        const multicastError = failures.find(r => r.message.includes('Multicast'));
        const broadcastError = failures.find(r => r.message.includes('Broadcast'));

        expect(multicastError).toBeDefined();
        expect(broadcastError).toBeDefined();

        expect(multicastError?.ruleId).toBe('NET-IP-001');
    });

    test('/32 loopback addresses should be valid', () => {
        const config = `
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });

    // Dynamic IP assignment tests - should not trigger false positives
    test('ip address dhcp should pass (dynamic assignment)', () => {
        const config = `
interface GigabitEthernet0/0
 ip address dhcp
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);

        const infoResults = results.filter(r => r.passed && r.message.includes('Dynamic IP'));
        expect(infoResults).toHaveLength(1);
    });

    test('ip address dhcp client-id should pass (dynamic assignment)', () => {
        const config = `
interface GigabitEthernet0/0
 ip address dhcp client-id GigabitEthernet0/0
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });

    test('ip address negotiated should pass (PPP dynamic)', () => {
        const config = `
interface Dialer1
 ip address negotiated
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });

    test('ip address ppp-negotiated should pass (PPP dynamic)', () => {
        const config = `
interface Serial0/0
 ip address ppp-negotiated
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });

    test('ip address pool should pass (pool assignment)', () => {
        const config = `
interface Virtual-Template1
 ip address pool MYPOOL
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });

    test('ip address auto should pass (auto assignment)', () => {
        const config = `
interface GigabitEthernet0/1
 ip address auto
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ipRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });
});

describe('All Rules Integration', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    test('allRules array should contain multiple rules', () => {
        expect(allRules.length).toBeGreaterThan(1);
    });

    test('valid-config.txt should pass all rules', async () => {
        const configPath = join(fixturesDir, 'valid-config.txt');
        const config = await readFile(configPath, 'utf-8');

        const nodes = parser.parse(config);
        const results = engine.run(nodes, allRules);

        // Only check for errors, not warnings
        const errors = results.filter(r => !r.passed && r.level === 'error');

        expect(errors).toHaveLength(0);
    });
});

describe('OSPF Network Best Practice (NET-OSPF-001)', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();
    const ospfRules = [OspfNetworkBestPractice];

    test('should pass with interface IP and 0.0.0.0 wildcard', () => {
        const config = `
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
router ospf 1
 network 1.1.1.1 0.0.0.0 area 0
 network 10.0.0.1 0.0.0.0 area 0
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ospfRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });

    test('should warn when using broad wildcard instead of exact match', () => {
        const config = `
interface GigabitEthernet0/0
 ip address 192.168.0.1 255.255.255.0
router ospf 1
 network 192.168.0.0 0.0.0.255 area 0
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ospfRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(1);
        expect(failures[0]?.message).toContain('broad wildcard');
        expect(failures[0]?.ruleId).toBe('NET-OSPF-001');
    });

    test('should warn when network IP does not match any interface', () => {
        const config = `
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
router ospf 1
 network 192.168.1.1 0.0.0.0 area 0
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ospfRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(1);
        expect(failures[0]?.message).toContain('does not match any configured interface IP');
    });

    test('should warn when broad wildcard does not match any interface subnet', () => {
        const config = `
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
router ospf 1
 network 192.168.0.0 0.0.0.255 area 0
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ospfRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(1);
        // Should warn about both: broad wildcard AND no matching interface subnet
        expect(failures[0]?.message).toContain('broad wildcard');
        expect(failures[0]?.message).toContain('does not match any configured interface subnet');
    });

    test('should pass when no network statements in OSPF', () => {
        const config = `
router ospf 1
 router-id 1.1.1.1
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ospfRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(0);
    });

    test('should handle multiple OSPF network issues', () => {
        const config = `
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
router ospf 1
 network 2.2.2.2 0.0.0.0 area 0
 network 10.0.0.0 0.0.0.7 area 1
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, ospfRules);

        const failures = results.filter(r => !r.passed);
        expect(failures).toHaveLength(1);
        // Should contain warnings for both network statements
        expect(failures[0]?.message).toContain('2.2.2.2');
        expect(failures[0]?.message).toContain('10.0.0.0 0.0.0.7');
    });
});

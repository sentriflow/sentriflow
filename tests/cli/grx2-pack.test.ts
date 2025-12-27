/**
 * CLI Integration Tests for GRX2 Pack Support
 *
 * Tests:
 * - T014: Basic CLI integration tests for --grx2-pack, --strict-grx2, --show-machine-id
 * - T031: Environment variable tests (SENTRIFLOW_LICENSE_KEY)
 * - T036: Graceful degradation tests (warning on failure, --strict-grx2 mode)
 *
 * NOTE: These tests generate GRX2 fixtures dynamically using the actual machine ID
 * to ensure proper decryption during testing.
 *
 * @module tests/cli/grx2-pack.test
 */
import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  TEST_LICENSE_KEY,
  buildExtendedGRX2Pack,
} from '../fixtures/generate-grx2-fixtures';
import { getMachineId } from '@sentriflow/core';

// =============================================================================
// Test Constants
// =============================================================================

const PROJECT_ROOT = process.cwd();
// Use .exe if it exists (Windows/WSL), otherwise use plain binary (Linux/macOS CI)
const CLI_PATH = existsSync(join(PROJECT_ROOT, 'sentriflow.exe'))
  ? join(PROJECT_ROOT, 'sentriflow.exe')
  : join(PROJECT_ROOT, 'sentriflow');
const TEMP_DIR = join(PROJECT_ROOT, '.tmp', 'test-cli-grx2');

// Machine ID will be populated in beforeAll
let REAL_MACHINE_ID: string;

// Dynamic fixture paths (generated in beforeAll)
const VALID_PACK_PATH = join(TEMP_DIR, 'valid-pack.grx2');
const CORRUPTED_PACK_PATH = join(TEMP_DIR, 'corrupted-pack.grx2');
const SECOND_VALID_PACK_PATH = join(TEMP_DIR, 'second-valid.grx2');
const TEST_CONFIG_PATH = join(TEMP_DIR, 'test-router.cfg');

// =============================================================================
// Dynamic Fixture Generators (using real machine ID)
// =============================================================================

/**
 * Generate a valid GRX2 pack with the real machine ID
 */
function generateValidPackForMachine(machineId: string): Buffer {
  const rulePack = {
    name: 'test-pack',
    version: '1.0.0',
    publisher: 'netsectech',
    description: 'Test rule pack for CLI integration tests',
    rules: [
      {
        id: 'TEST-001',
        selector: 'interface',
        metadata: { level: 'error', obu: 'network', owner: 'test', description: 'Test rule 1' },
      },
      {
        id: 'TEST-002',
        selector: 'router bgp',
        metadata: { level: 'warning', obu: 'network', owner: 'test', description: 'Test rule 2' },
      },
    ],
  };

  const content = Buffer.from(JSON.stringify(rulePack), 'utf8');
  return buildExtendedGRX2Pack(content, TEST_LICENSE_KEY, machineId, 1, 1);
}

/**
 * Generate a second valid pack with different rules
 */
function generateSecondValidPackForMachine(machineId: string): Buffer {
  const rulePack = {
    name: 'test-pack-2',
    version: '1.0.0',
    publisher: 'netsectech',
    description: 'Second test rule pack',
    rules: [
      {
        id: 'TEST-003',
        selector: 'ip route',
        metadata: { level: 'info', obu: 'routing', owner: 'test', description: 'Test rule 3' },
      },
    ],
  };

  const content = Buffer.from(JSON.stringify(rulePack), 'utf8');
  return buildExtendedGRX2Pack(content, TEST_LICENSE_KEY, machineId, 1, 1);
}

/**
 * Generate a corrupted pack (invalid magic bytes)
 */
function generateCorruptedPack(): Buffer {
  // Create a pack with valid structure but corrupted magic bytes
  const validPack = generateValidPackForMachine('');
  const corrupted = Buffer.from(validPack);
  corrupted.write('XXXX', 0, 'ascii'); // Corrupt the magic bytes
  return corrupted;
}

/**
 * Create test config file for scanning
 */
function createTestConfig(path: string): void {
  const content = `! Test router config for GRX2 integration tests
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
router bgp 65000
 neighbor 10.0.0.2 remote-as 65001
!
`;
  writeFileSync(path, content);
}

// =============================================================================
// Test Setup/Teardown
// =============================================================================

beforeAll(async () => {
  // Get the real machine ID for fixture generation
  REAL_MACHINE_ID = await getMachineId();

  // Create temp directory
  if (!existsSync(TEMP_DIR)) {
    mkdirSync(TEMP_DIR, { recursive: true });
  }

  // Generate test config file
  createTestConfig(TEST_CONFIG_PATH);

  // Generate GRX2 packs with real machine ID
  const validPack = generateValidPackForMachine(REAL_MACHINE_ID);
  writeFileSync(VALID_PACK_PATH, validPack);

  const secondValidPack = generateSecondValidPackForMachine(REAL_MACHINE_ID);
  writeFileSync(SECOND_VALID_PACK_PATH, secondValidPack);

  // Generate corrupted pack
  const corruptedPack = generateCorruptedPack();
  writeFileSync(CORRUPTED_PACK_PATH, corruptedPack);
});

afterAll(() => {
  if (existsSync(TEMP_DIR)) {
    rmSync(TEMP_DIR, { recursive: true, force: true });
  }
});

// =============================================================================
// T014: Basic CLI Integration Tests
// =============================================================================

describe('T014: Basic CLI Integration Tests', () => {
  describe('--grx2-pack flag', () => {
    it('should load valid GRX2 pack and apply rules', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show GRX2 pack loading summary
      expect(stderr).toContain('GRX2 packs:');
      expect(stderr).toContain('1 of 1 loaded');

      // Output should be valid JSON with results
      const output = JSON.parse(stdout);
      expect(output).toHaveProperty('results');
    });

    it('should load multiple --grx2-pack flags together', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--grx2-pack', SECOND_VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show both packs loaded
      expect(stderr).toContain('GRX2 packs:');
      expect(stderr).toContain('2 of 2 loaded');

      // Output should be valid JSON
      const output = JSON.parse(stdout);
      expect(output).toHaveProperty('results');
    });
  });

  describe('--show-machine-id flag', () => {
    it('should display machine ID', async () => {
      const proc = Bun.spawn([CLI_PATH, '--show-machine-id'], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stdout = await new Response(proc.stdout).text();
      await proc.exited;

      // Should show machine ID output
      expect(stdout).toContain('Machine ID:');
      expect(stdout).toContain('Use this ID when requesting a machine-bound license');

      // Machine ID should be non-empty
      const match = stdout.match(/Machine ID: ([^\n]+)/);
      expect(match).toBeTruthy();
      expect(match?.[1]?.trim().length).toBeGreaterThan(0);
    });

    it('should exit successfully with --show-machine-id', async () => {
      const proc = Bun.spawn([CLI_PATH, '--show-machine-id'], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      await proc.exited;
      expect(proc.exitCode).toBe(0);
    });
  });

  describe('user-friendly error messages', () => {
    it('should show friendly error for corrupted pack', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', CORRUPTED_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show warning about failed pack
      expect(stderr).toContain('Warning:');
      expect(stderr).toContain('Failed to load GRX2 pack');
    });

    it('should show friendly error for non-existent pack', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', '/nonexistent/path.grx2',
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show warning about failed pack (file not found)
      expect(stderr).toContain('Warning:');
    });

    it('should show friendly error for invalid license key', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--license-key', 'wrong-license-key',
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show warning about decryption failure
      expect(stderr).toContain('Warning:');
      expect(stderr).toContain('Failed to load GRX2 pack');
    });
  });
});

// =============================================================================
// T031: Environment Variable Tests
// =============================================================================

describe('T031: Environment Variable Tests', () => {
  describe('SENTRIFLOW_LICENSE_KEY environment variable', () => {
    it('should use env var when --license-key not provided', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: {
          ...process.env,
          SENTRIFLOW_LICENSE_KEY: TEST_LICENSE_KEY,
        },
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should successfully load pack using env var
      expect(stderr).toContain('GRX2 packs:');
      expect(stderr).toContain('1 of 1 loaded');

      // Output should be valid JSON
      const output = JSON.parse(stdout);
      expect(output).toHaveProperty('results');
    });

    it('should prefer --license-key argument over env var', async () => {
      // Set wrong license in env, correct in CLI arg
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: {
          ...process.env,
          SENTRIFLOW_LICENSE_KEY: 'wrong-env-license-key',
        },
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should successfully load pack using CLI arg (not env var)
      expect(stderr).toContain('GRX2 packs:');
      expect(stderr).toContain('1 of 1 loaded');

      // Output should be valid JSON
      const output = JSON.parse(stdout);
      expect(output).toHaveProperty('results');
    });

    it('should show clear error when neither env var nor CLI arg provided', async () => {
      // Remove env var and don't provide CLI arg
      const envWithoutLicense = { ...process.env };
      delete envWithoutLicense.SENTRIFLOW_LICENSE_KEY;

      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: envWithoutLicense,
      });

      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show warning about missing license key
      expect(stderr).toContain('Warning:');
      expect(stderr).toContain('License key required');
      expect(stderr).toContain('SENTRIFLOW_LICENSE_KEY');
    });
  });
});

// =============================================================================
// T036: Graceful Degradation Tests
// =============================================================================

describe('T036: Graceful Degradation Tests', () => {
  describe('graceful degradation (default behavior)', () => {
    it('should show warning for failed pack and continue scanning', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', CORRUPTED_PACK_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show warning for corrupted pack
      expect(stderr).toContain('Warning:');
      expect(stderr).toContain('Failed to load GRX2 pack');

      // Should show summary with partial success
      expect(stderr).toContain('GRX2 packs:');
      expect(stderr).toContain('1 of 2 loaded');
      expect(stderr).toContain('1 failed');

      // Should still produce valid output (scan continued)
      const output = JSON.parse(stdout);
      expect(output).toHaveProperty('results');
    });

    it('should continue with other packs when one fails', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--grx2-pack', CORRUPTED_PACK_PATH,
        '--grx2-pack', SECOND_VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show summary: 2 of 3 loaded
      expect(stderr).toContain('GRX2 packs:');
      expect(stderr).toContain('2 of 3 loaded');

      // Should still produce valid output
      const output = JSON.parse(stdout);
      expect(output).toHaveProperty('results');
    });
  });

  describe('--strict-grx2 flag', () => {
    it('should fail immediately when pack load fails with --strict-grx2', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', CORRUPTED_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--strict-grx2',
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stderr = await new Response(proc.stderr).text();
      const exitCode = await proc.exited;

      // Should exit with error code
      expect(exitCode).not.toBe(0);

      // Should show error message
      expect(stderr).toContain('Error:');
      expect(stderr).toContain('Failed to load GRX2 pack');
    });

    it('should fail immediately with --strict-grx2 when license key missing', async () => {
      // Remove env var and don't provide CLI arg
      const envWithoutLicense = { ...process.env };
      delete envWithoutLicense.SENTRIFLOW_LICENSE_KEY;

      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--strict-grx2',
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: envWithoutLicense,
      });

      const stderr = await new Response(proc.stderr).text();
      const exitCode = await proc.exited;

      // Should exit with error code
      expect(exitCode).not.toBe(0);

      // Should show error message about missing license
      expect(stderr).toContain('Error:');
      expect(stderr).toContain('License key required');
    });

    it('should succeed with --strict-grx2 when all packs load successfully', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--strict-grx2',
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show successful loading
      expect(stderr).toContain('GRX2 packs:');
      expect(stderr).toContain('1 of 1 loaded');

      // Should produce valid output
      const output = JSON.parse(stdout);
      expect(output).toHaveProperty('results');
    });
  });

  describe('pack loading summary', () => {
    it('should show "X of Y packs loaded" summary', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--grx2-pack', SECOND_VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show summary
      expect(stderr).toMatch(/GRX2 packs: \d+ of \d+ loaded/);
    });

    it('should show rule count in summary', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show rule count in summary (e.g., "1 of 1 loaded (X rules)")
      expect(stderr).toMatch(/GRX2 packs:.*\d+ rules/);
    });

    it('should show failed count when packs fail', async () => {
      const proc = Bun.spawn([
        CLI_PATH,
        TEST_CONFIG_PATH,
        '--grx2-pack', VALID_PACK_PATH,
        '--grx2-pack', CORRUPTED_PACK_PATH,
        '--license-key', TEST_LICENSE_KEY,
        '--allow-external',
      ], {
        stdout: 'pipe',
        stderr: 'pipe',
        env: { ...process.env },
      });

      const stderr = await new Response(proc.stderr).text();
      await proc.exited;

      // Should show failed count
      expect(stderr).toContain('1 failed');
    });
  });
});

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

describe('Edge Cases', () => {
  it('should handle --grx2-pack with --list-rules', async () => {
    const proc = Bun.spawn([
      CLI_PATH,
      '--grx2-pack', VALID_PACK_PATH,
      '--license-key', TEST_LICENSE_KEY,
      '--list-rules',
      '--allow-external',
    ], {
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env },
    });

    const stdout = await new Response(proc.stdout).text();
    await proc.exited;

    // Should list rules including those from the pack
    expect(stdout).toContain('ID');
    expect(stdout).toContain('CATEGORY');
  });

  it('should handle empty license key gracefully', async () => {
    const proc = Bun.spawn([
      CLI_PATH,
      TEST_CONFIG_PATH,
      '--grx2-pack', VALID_PACK_PATH,
      '--license-key', '',
      '--allow-external',
    ], {
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env },
    });

    const stderr = await new Response(proc.stderr).text();
    await proc.exited;

    // Should show warning about missing license key
    expect(stderr).toContain('Warning:');
    expect(stderr).toContain('License key required');
  });

  it('should handle GRX2 pack with directory scanning', async () => {
    const proc = Bun.spawn([
      CLI_PATH,
      '--directory', TEMP_DIR,
      '--grx2-pack', VALID_PACK_PATH,
      '--license-key', TEST_LICENSE_KEY,
      '--allow-external',
    ], {
      stdout: 'pipe',
      stderr: 'pipe',
      env: { ...process.env },
    });

    const stdout = await new Response(proc.stdout).text();
    const stderr = await new Response(proc.stderr).text();
    await proc.exited;

    // Should show GRX2 pack loaded
    expect(stderr).toContain('GRX2 packs:');

    // Should produce valid JSON output
    const output = JSON.parse(stdout);
    expect(output).toHaveProperty('summary');
    expect(output).toHaveProperty('files');
  });
});

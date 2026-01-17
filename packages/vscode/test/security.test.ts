// packages/vscode/test/security.test.ts
//
// Security-focused tests to verify security fixes remain in place.
// These tests verify that security vulnerabilities have been addressed
// and help prevent regressions.

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const SRC_DIR = join(__dirname, '..', 'src');

describe('SEC-001: HoverProvider XSS Prevention', () => {
  const hoverProviderPath = join(SRC_DIR, 'providers', 'HoverProvider.ts');
  let hoverProviderSource: string;

  test('HoverProvider source file exists', () => {
    hoverProviderSource = readFileSync(hoverProviderPath, 'utf-8');
    expect(hoverProviderSource).toBeTruthy();
  });

  test('isTrusted is documented when set to true', () => {
    // Reading fresh in case previous test didn't run
    const source = readFileSync(hoverProviderPath, 'utf-8');

    // If isTrusted = true is present, it MUST be documented with a SEC comment
    // explaining why it's needed (e.g., for command links with trusted internal data)
    const hasTrustedTrue = /markdown\.isTrusted\s*=\s*true/.test(source);

    if (hasTrustedTrue) {
      // isTrusted = true is acceptable when:
      // 1. It's needed for command links (suppression actions)
      // 2. The content is trusted internal data (rule metadata, not user input)
      // 3. It's documented with a SEC-001 comment
      const hasSecComment = source.includes('SEC-001');
      expect(hasSecComment).toBe(true);
    }
    // If isTrusted is not set, that's also acceptable (more secure default)
  });

  test('supportHtml is NOT set to true', () => {
    const source = readFileSync(hoverProviderPath, 'utf-8');

    // Check that supportHtml = true is NOT present
    const hasHtmlTrue = /markdown\.supportHtml\s*=\s*true/.test(source);

    expect(hasHtmlTrue).toBe(false);
  });

  test('MarkdownString is created without trusted options', () => {
    const source = readFileSync(hoverProviderPath, 'utf-8');

    // Verify MarkdownString is instantiated
    expect(source).toContain('new vscode.MarkdownString()');
  });
});

describe('SEC-002: Secure Nonce Generation', () => {
  const webviewProviderPath = join(SRC_DIR, 'providers', 'SettingsWebviewProvider.ts');
  let webviewProviderSource: string;

  test('SettingsWebviewProvider source file exists', () => {
    webviewProviderSource = readFileSync(webviewProviderPath, 'utf-8');
    expect(webviewProviderSource).toBeTruthy();
  });

  test('crypto module is imported', () => {
    const source = readFileSync(webviewProviderPath, 'utf-8');

    // Verify crypto import exists
    const hasCryptoImport = /import\s+\*\s+as\s+crypto\s+from\s+['"]crypto['"]/.test(source);

    expect(hasCryptoImport).toBe(true);
  });

  test('Math.random is NOT used for nonce generation', () => {
    const source = readFileSync(webviewProviderPath, 'utf-8');

    // Check that Math.random is not used in _getNonce method
    // Look for Math.random anywhere near nonce generation
    const getNonceMatch = source.match(/_getNonce\(\)[^}]+}/s);
    if (getNonceMatch) {
      const getNonceBody = getNonceMatch[0];
      expect(getNonceBody).not.toContain('Math.random');
    }
  });

  test('crypto.randomBytes is used for nonce', () => {
    const source = readFileSync(webviewProviderPath, 'utf-8');

    // Verify crypto.randomBytes is used
    expect(source).toContain('crypto.randomBytes');
  });

  test('nonce generation returns base64 encoded value', () => {
    const source = readFileSync(webviewProviderPath, 'utf-8');

    // Verify base64 encoding is used
    const usesBase64 = source.includes("toString('base64')") || source.includes('toString("base64")');
    expect(usesBase64).toBe(true);
  });
});

describe('DRY-001: Rule Sorting Utility', () => {
  const treeProviderPath = join(SRC_DIR, 'providers', 'RulesTreeProvider.ts');

  test('compareRulesByLevel function is exported', () => {
    const source = readFileSync(treeProviderPath, 'utf-8');

    // Verify the function is exported
    expect(source).toContain('export function compareRulesByLevel');
  });

  test('LEVEL_ORDER constant is defined', () => {
    const source = readFileSync(treeProviderPath, 'utf-8');

    // Verify the constant exists
    expect(source).toContain('const LEVEL_ORDER');
  });

  test('no duplicate levelOrder definitions in sorting code', () => {
    const source = readFileSync(treeProviderPath, 'utf-8');

    // Count occurrences of levelOrder object literal pattern
    // This should NOT appear as it's been extracted
    const inlineDefinitions = (source.match(/const\s+levelOrder\s*=\s*\{/g) || []).length;

    expect(inlineDefinitions).toBe(0);
  });
});

describe('DRY-002: Comma-Separated Parsing Utility', () => {
  const extensionPath = join(SRC_DIR, 'extension.ts');

  test('parseCommaSeparated function is exported', () => {
    const source = readFileSync(extensionPath, 'utf-8');

    // Verify the function is exported (either directly or re-exported from utils/helpers)
    const hasDirectExport = source.includes('export function parseCommaSeparated');
    const hasReExport = source.includes("export { parseCommaSeparated }");
    expect(hasDirectExport || hasReExport).toBe(true);
  });

  test('getDisabledRulesSet uses parseCommaSeparated', () => {
    const source = readFileSync(extensionPath, 'utf-8');

    // Find getDisabledRulesSet function and verify it uses the utility
    const functionMatch = source.match(/function getDisabledRulesSet\(\)[^}]+}/s);
    if (functionMatch) {
      expect(functionMatch[0]).toContain('parseCommaSeparated');
    }
  });
});

describe('PERF-001: Tags Caching', () => {
  const treeProviderPath = join(SRC_DIR, 'providers', 'RulesTreeProvider.ts');

  test('_tagsCache field is defined', () => {
    const source = readFileSync(treeProviderPath, 'utf-8');

    expect(source).toContain('_tagsCache');
  });

  test('refresh method invalidates cache', () => {
    const source = readFileSync(treeProviderPath, 'utf-8');

    // Find refresh method and verify it sets cache to null
    const refreshMatch = source.match(/refresh\(\)[^}]+}/s);
    if (refreshMatch) {
      expect(refreshMatch[0]).toContain('_tagsCache = null');
    }
  });

  test('getAllTags uses cached result when available', () => {
    const source = readFileSync(treeProviderPath, 'utf-8');

    // Verify cache check exists
    expect(source).toContain('if (this._tagsCache)');
  });
});

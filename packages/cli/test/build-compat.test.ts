import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { execFileSync } from 'child_process';

const distPath = resolve(import.meta.dir, '../dist/index.js');

describe('ESM bundle CJS compatibility', () => {
  test('banner contains createRequire polyfill', () => {
    const source = readFileSync(distPath, 'utf-8');
    expect(source).toContain("import { createRequire } from 'module'");
    expect(source).toContain('const require = createRequire(import.meta.url)');
  });

  test('bundle loads without "Dynamic require" crash', () => {
    const output = execFileSync('node', [distPath, '--help'], {
      encoding: 'utf-8',
      timeout: 10_000,
    });
    expect(output).toContain('sentriflow');
  });
});

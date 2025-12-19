#!/usr/bin/env node

/**
 * Version bump script for SentriFlow monorepo.
 * Updates version in all package.json files.
 *
 * Usage:
 *   node scripts/bump-version.mjs <version>
 *   node scripts/bump-version.mjs 1.3.0
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');

const version = process.argv[2];

if (!version) {
  console.error('Usage: node scripts/bump-version.mjs <version>');
  console.error('Example: node scripts/bump-version.mjs 1.3.0');
  process.exit(1);
}

// Validate semver format
if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) {
  console.error(`Invalid version format: ${version}`);
  console.error('Expected format: X.Y.Z or X.Y.Z-tag');
  process.exit(1);
}

const packagePaths = [
  'package.json',
  'packages/core/package.json',
  'packages/cli/package.json',
  'packages/rules-default/package.json',
  'packages/vscode/package.json',
];

console.log(`Bumping version to ${version}\n`);

for (const pkgPath of packagePaths) {
  const fullPath = join(rootDir, pkgPath);
  const pkg = JSON.parse(readFileSync(fullPath, 'utf-8'));
  const oldVersion = pkg.version;
  pkg.version = version;
  writeFileSync(fullPath, JSON.stringify(pkg, null, 2) + '\n');
  console.log(`  ${pkgPath}: ${oldVersion} → ${version}`);
}

console.log('\nDone! Remember to rebuild packages before publishing.');

#!/usr/bin/env node

/**
 * Version bump script for SentriFlow monorepo.
 * npm packages and VS Code extension have independent versioning.
 *
 * Usage:
 *   node scripts/bump-version.mjs <version>           # npm packages only
 *   node scripts/bump-version.mjs --vscode <version>  # VS Code extension only
 *
 * Examples:
 *   node scripts/bump-version.mjs 1.3.0
 *   node scripts/bump-version.mjs --vscode 1.0.0
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');

const isVscode = process.argv[2] === '--vscode';
const version = isVscode ? process.argv[3] : process.argv[2];

if (!version) {
  console.error('Usage:');
  console.error('  node scripts/bump-version.mjs <version>           # npm packages');
  console.error('  node scripts/bump-version.mjs --vscode <version>  # VS Code extension');
  console.error('');
  console.error('Examples:');
  console.error('  node scripts/bump-version.mjs 1.3.0');
  console.error('  node scripts/bump-version.mjs --vscode 1.0.0');
  process.exit(1);
}

// Validate semver format
if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) {
  console.error(`Invalid version format: ${version}`);
  console.error('Expected format: X.Y.Z or X.Y.Z-tag');
  process.exit(1);
}

// npm packages (core, cli, rules-default) share version with root
const npmPackagePaths = [
  'package.json',
  'packages/core/package.json',
  'packages/cli/package.json',
  'packages/rules-default/package.json',
];

// VS Code extension has independent versioning
const vscodePackagePaths = [
  'packages/vscode/package.json',
];

const packagePaths = isVscode ? vscodePackagePaths : npmPackagePaths;
const target = isVscode ? 'VS Code extension' : 'npm packages';

console.log(`Bumping ${target} to ${version}\n`);

for (const pkgPath of packagePaths) {
  const fullPath = join(rootDir, pkgPath);
  const pkg = JSON.parse(readFileSync(fullPath, 'utf-8'));
  const oldVersion = pkg.version;
  pkg.version = version;
  writeFileSync(fullPath, JSON.stringify(pkg, null, 2) + '\n');
  console.log(`  ${pkgPath}: ${oldVersion} → ${version}`);
}

console.log('\nDone! Remember to rebuild packages before publishing.');

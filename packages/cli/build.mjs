import * as esbuild from 'esbuild';
import { readFileSync } from 'fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));

await esbuild.build({
  entryPoints: ['./index.ts'],
  bundle: true,
  outfile: 'dist/index.js',
  format: 'esm',
  platform: 'node',
  target: 'node18',
  external: ['commander'],
  banner: {
    js: [
      '#!/usr/bin/env node',
      "import { createRequire } from 'module';",
      'const require = createRequire(import.meta.url);',
    ].join('\n'),
  },
  define: {
    __VERSION__: JSON.stringify(pkg.version),
  },
});

console.log(`Built CLI v${pkg.version}`);

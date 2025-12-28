import * as esbuild from 'esbuild';
import { readFileSync } from 'fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));

const isWatch = process.argv.includes('--watch');
const isDev = process.argv.includes('--dev');

const buildOptions = {
  entryPoints: ['./src/extension.ts'],
  bundle: true,
  outfile: 'dist/extension.js',
  external: ['vscode'],
  format: 'cjs',
  platform: 'node',
  define: {
    __VERSION__: JSON.stringify(pkg.version),
  },
  alias: {
    // Core package sub-paths (more specific first)
    '@sentriflow/core/grx2-loader': '../core/src/grx2-loader/index.ts',
    '@sentriflow/core/helpers/arista': '../core/src/helpers/arista/index.ts',
    '@sentriflow/core/helpers/aruba': '../core/src/helpers/aruba/index.ts',
    '@sentriflow/core/helpers/cisco': '../core/src/helpers/cisco/index.ts',
    '@sentriflow/core/helpers/common': '../core/src/helpers/common/index.ts',
    '@sentriflow/core/helpers/cumulus': '../core/src/helpers/cumulus/index.ts',
    '@sentriflow/core/helpers/extreme': '../core/src/helpers/extreme/index.ts',
    '@sentriflow/core/helpers/fortinet': '../core/src/helpers/fortinet/index.ts',
    '@sentriflow/core/helpers/huawei': '../core/src/helpers/huawei/index.ts',
    '@sentriflow/core/helpers/juniper': '../core/src/helpers/juniper/index.ts',
    '@sentriflow/core/helpers/mikrotik': '../core/src/helpers/mikrotik/index.ts',
    '@sentriflow/core/helpers/nokia': '../core/src/helpers/nokia/index.ts',
    '@sentriflow/core/helpers/paloalto': '../core/src/helpers/paloalto/index.ts',
    '@sentriflow/core/helpers/vyos': '../core/src/helpers/vyos/index.ts',
    '@sentriflow/core/helpers': '../core/src/helpers/index.ts',
    '@sentriflow/core': '../core/src/index.ts',
    // Rule helpers (legacy paths)
    '@sentriflow/rule-helpers/arista': '../rule-helpers/src/arista/index.ts',
    '@sentriflow/rule-helpers/aruba': '../rule-helpers/src/aruba/index.ts',
    '@sentriflow/rule-helpers/cisco': '../rule-helpers/src/cisco/index.ts',
    '@sentriflow/rule-helpers/common': '../rule-helpers/src/common/index.ts',
    '@sentriflow/rule-helpers/cumulus': '../rule-helpers/src/cumulus/index.ts',
    '@sentriflow/rule-helpers/extreme': '../rule-helpers/src/extreme/index.ts',
    '@sentriflow/rule-helpers/fortinet': '../rule-helpers/src/fortinet/index.ts',
    '@sentriflow/rule-helpers/huawei': '../rule-helpers/src/huawei/index.ts',
    '@sentriflow/rule-helpers/juniper': '../rule-helpers/src/juniper/index.ts',
    '@sentriflow/rule-helpers/mikrotik': '../rule-helpers/src/mikrotik/index.ts',
    '@sentriflow/rule-helpers/nokia': '../rule-helpers/src/nokia/index.ts',
    '@sentriflow/rule-helpers/paloalto': '../rule-helpers/src/paloalto/index.ts',
    '@sentriflow/rule-helpers/vyos': '../rule-helpers/src/vyos/index.ts',
  },
  ...(isDev ? {} : {
    minify: true,
    treeShaking: true,
    drop: ['debugger'],
  }),
  charset: 'utf8',
};

if (isWatch) {
  const ctx = await esbuild.context(buildOptions);
  await ctx.watch();
  console.log(`Watching for changes... (v${pkg.version})`);
} else {
  await esbuild.build(buildOptions);
  console.log(`Built extension v${pkg.version}${isDev ? ' (dev)' : ''}`);
}

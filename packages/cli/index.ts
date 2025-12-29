declare const __VERSION__: string;

import { Command } from 'commander';
import {
  SchemaAwareParser,
  RuleEngine,
  SentriflowError,
  MAX_CONFIG_SIZE,
  detectVendor,
  getVendor,
  getAvailableVendors,
  extractIPSummary,
  filterIPSummary,
  InputValidationError,
  // GRX2 Extended Pack Support
  getMachineId,
  loadExtendedPack,
  EncryptedPackError,
} from '@sentriflow/core';
import type { VendorSchema } from '@sentriflow/core';
import type { IRule, RuleResult, Tag } from '@sentriflow/core';
import { readFile } from 'fs/promises';
import { statSync } from 'fs';
import { resolve, dirname, basename } from 'path';
import { generateSarif, generateMultiFileSarif } from './src/sarif';
import type { FileResults } from './src/sarif';
import {
  resolveRules,
  findConfigFile,
  ruleAppliesToVendor,
  mergeDirectoryOptions,
  loadConfigFile,
  type DirectoryConfig,
} from './src/config';
import { validateInputFilePath } from './src/security/pathValidator';
import {
  scanDirectory,
  validateDirectoryPath,
  DEFAULT_CONFIG_EXTENSIONS,
  validateRegexPattern,
} from './src/scanner/DirectoryScanner';
import {
  readStdin,
  validateStdinArgument,
  isStdinRequested,
} from './src/loaders/stdin';

/**
 * Enriched rule result with category and tags from the rule definition.
 * Used for JSON output to include rule metadata alongside results.
 */
interface EnrichedResult extends RuleResult {
  /** Rule category for grouping (e.g., 'authentication', 'routing') */
  category?: string | string[];
  /** Typed tags for multi-dimensional rule categorization */
  tags: Tag[];
}

/**
 * Enriches rule results with category and tags from the corresponding rule definitions.
 * @param results - Array of rule results from the engine
 * @param rules - Array of rule definitions to lookup metadata
 * @returns Array of enriched results with category and tags
 */
function enrichResultsWithRuleMetadata(
  results: RuleResult[],
  rules: IRule[]
): EnrichedResult[] {
  const ruleMap = new Map(rules.map((r) => [r.id, r]));
  return results.map((result) => {
    const rule = ruleMap.get(result.ruleId);
    return {
      ...result,
      category: rule?.category,
      tags: rule?.metadata.tags ?? [],
    };
  });
}

const program = new Command();

program
  .name('sentriflow')
  .description('SentriFlow Network Configuration Validator')
  .version(__VERSION__)
  .argument('[files...]', 'Path(s) to configuration file(s) (supports multiple files)')
  .option('--ast', 'Output the AST instead of rule results')
  .option('-f, --format <format>', 'Output format (json, sarif)', 'json')
  .option('-q, --quiet', 'Only output failures (suppress passed results)')
  .option('-c, --config <path>', 'Path to config file (default: auto-detect)')
  .option('--no-config', 'Ignore config file')
  .option('-r, --rules <path>', 'Additional rules file to load (legacy)')
  .option(
    '--pack <path...>',
    'Path(s) to rule pack(s) (auto-detects format: .grx2, .grpx, or unencrypted)'
  )
  .option(
    '--license-key <key>',
    'License key for encrypted rule packs (or set SENTRIFLOW_LICENSE_KEY)'
  )
  .option(
    '--strict-packs',
    'Fail immediately if any pack cannot be loaded (default: warn and continue)'
  )
  .option(
    '--show-machine-id',
    'Display the current machine ID (for license binding support)'
  )
  .option(
    '--json-rules <path...>',
    'Path(s) to JSON rules file(s), can specify multiple'
  )
  .option('-d, --disable <ids>', 'Comma-separated rule IDs to disable', (val) =>
    val.split(',')
  )
  .option('--list-rules', 'List all active rules and exit')
  .option('--list-categories', 'List all rule categories with counts and exit')
  .option(
    '--category <category>',
    'Filter rules by category (use with --list-rules)'
  )
  .option(
    '--list-format <format>',
    'Output format for --list-rules: table, json, csv (default: table)',
    'table'
  )
  .option('--relative-paths', 'Use relative paths in SARIF output')
  .option(
    '--allow-external',
    'Allow reading files outside the current directory (use with caution)'
  )
  .option(
    '-v, --vendor <vendor>',
    `Vendor type (${getAvailableVendors().join(', ')}, auto)`,
    'auto'
  )
  .option('--list-vendors', 'List all supported vendors and exit')
  .option('-D, --directory <path>', 'Scan all config files in a directory')
  .option(
    '-R, --recursive',
    'Scan directories recursively (use with --directory)'
  )
  .option(
    '--glob <pattern>',
    'Glob pattern for file matching (e.g., "*.cfg")',
    (val) => val
  )
  .option(
    '--extensions <exts>',
    `File extensions to include (comma-separated, default: ${DEFAULT_CONFIG_EXTENSIONS.slice(
      0,
      5
    ).join(',')},...)`,
    (val) => val.split(',')
  )
  .option(
    '--exclude <patterns>',
    'Exclude patterns (comma-separated glob patterns)',
    (val) => val.split(',')
  )
  .option(
    '--exclude-pattern <pattern...>',
    'Regex pattern(s) to exclude files (JavaScript regex syntax, can specify multiple)'
  )
  .option(
    '--max-depth <number>',
    'Maximum recursion depth for directory scanning (use with -R)',
    (val) => parseInt(val, 10)
  )
  .option('--progress', 'Show progress during directory scanning')
  .option(
    '--filter-special-ips',
    'Filter out special IP ranges (loopback, multicast, reserved, broadcast) from IP summary'
  )
  .action(async (files: string[], options) => {
    try {
      // Show machine ID mode (for license binding support)
      if (options.showMachineId) {
        try {
          const machineId = await getMachineId();
          console.log(`Machine ID: ${machineId}`);
          console.log(`\nUse this ID when requesting a machine-bound license.`);
        } catch (error) {
          console.error('Error: Failed to retrieve machine ID');
          console.error(error instanceof Error ? error.message : String(error));
          process.exit(1);
        }
        return;
      }

      // List vendors mode
      if (options.listVendors) {
        console.log('Supported vendors:\n');
        for (const vendorId of getAvailableVendors()) {
          const vendor = getVendor(vendorId);
          const braceInfo = vendor.useBraceHierarchy
            ? '(brace-based)'
            : '(indentation-based)';
          console.log(`  ${vendorId.padEnd(16)} - ${vendor.name} ${braceInfo}`);
        }
        console.log(
          `\n  auto             - Auto-detect vendor from config content`
        );
        console.log(`\nUse: sentriflow --vendor <vendor> <file>`);
        return;
      }

      // Resolve vendor early for rule filtering
      let vendorId: string | undefined;
      if (options.vendor !== 'auto') {
        try {
          getVendor(options.vendor); // Validate vendor
          vendorId = options.vendor;
        } catch {
          // Invalid vendor will be caught later during scanning
        }
      }

      // SEC-011: Enforce CWD boundary by default (use --allow-external to bypass)
      const workingDir = process.cwd();
      const allowedBaseDirs = options.allowExternal ? undefined : [workingDir];

      // FR-003: Validate and compile regex exclusion patterns at startup
      const excludePatterns: RegExp[] = [];
      if (options.excludePattern) {
        for (const pattern of options.excludePattern) {
          const result = validateRegexPattern(pattern);
          if (!result.valid) {
            console.error(`Error: Invalid regex pattern '${pattern}'`);
            console.error(`  ${result.error}`);
            process.exit(2);
          }
          excludePatterns.push(result.regex!);
        }
      }

      // SEC-012: Resolve license key from CLI option or environment variable
      const licenseKey =
        options.licenseKey || process.env.SENTRIFLOW_LICENSE_KEY;

      // Resolve rules from config + CLI options
      const firstFile = files.length > 0 ? files[0] : undefined;
      const configSearchDir = firstFile ? dirname(resolve(firstFile)) : workingDir;
      const rules = await resolveRules({
        configPath: options.config,
        noConfig: options.config === false, // --no-config sets this to false
        rulesPath: options.rules,
        packPaths: options.pack, // Unified pack loading with auto-format detection
        licenseKey, // From CLI or SENTRIFLOW_LICENSE_KEY env var
        strictPacks: options.strictPacks, // Fail on pack load errors
        jsonRulesPaths: options.jsonRules, // JSON rules files
        disableIds: options.disable ?? [],
        vendorId,
        cwd: configSearchDir,
        allowedBaseDirs, // SEC-011: Pass allowed base dirs for rule file validation
      });

      // Load config file for additional options (filterSpecialIps)
      // CLI option takes precedence over config file
      let filterSpecialIps = options.filterSpecialIps ?? false;
      if (!options.filterSpecialIps && options.config !== false) {
        const configPath = options.config ?? findConfigFile(configSearchDir);
        if (configPath) {
          try {
            const config = await loadConfigFile(configPath, allowedBaseDirs);
            if (config.filterSpecialIps) {
              filterSpecialIps = true;
            }
          } catch {
            // Config loading may fail, already handled by resolveRules
          }
        }
      }

      // List categories mode
      if (options.listCategories) {
        const counts = new Map<string, number>();

        for (const rule of rules) {
          const cats = Array.isArray(rule.category)
            ? rule.category
            : [rule.category ?? 'uncategorized'];
          for (const cat of cats) {
            counts.set(cat, (counts.get(cat) ?? 0) + 1);
          }
        }

        // Sort by count descending
        const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);

        console.log('CATEGORY              COUNT');
        console.log('─'.repeat(35));
        for (const [cat, count] of sorted) {
          console.log(`${cat.padEnd(22)}${count}`);
        }
        console.log('─'.repeat(35));
        console.log(`TOTAL                 ${rules.length}`);
        return;
      }

      // List rules mode
      if (options.listRules) {
        // Apply category filter if specified
        let filteredRules = rules;
        if (options.category) {
          filteredRules = rules.filter((r) => {
            const cats = Array.isArray(r.category)
              ? r.category
              : [r.category];
            return cats.includes(options.category);
          });
        }

        // Output based on format
        if (options.listFormat === 'json') {
          const output = filteredRules.map((r) => ({
            id: r.id,
            category: r.category,
            vendor: r.vendor,
            level: r.metadata.level,
            obu: r.metadata.obu,
            description: r.metadata.description,
            tags: r.metadata.tags,
          }));
          console.log(JSON.stringify(output, null, 2));
        } else if (options.listFormat === 'csv') {
          console.log('id,category,vendor,level,obu,description');
          for (const rule of filteredRules) {
            const cat = Array.isArray(rule.category)
              ? rule.category.join(';')
              : (rule.category ?? '');
            const vendor = Array.isArray(rule.vendor)
              ? rule.vendor.join(';')
              : (rule.vendor ?? 'common');
            const desc = (rule.metadata.description ?? '').replace(/"/g, '""');
            console.log(
              `"${rule.id}","${cat}","${vendor}","${rule.metadata.level}","${rule.metadata.obu}","${desc}"`
            );
          }
        } else {
          // Table format (default)
          console.log(
            'ID                CATEGORY              VENDOR          LEVEL    OBU'
          );
          console.log('─'.repeat(85));
          for (const rule of filteredRules) {
            const cat = Array.isArray(rule.category)
              ? rule.category[0] ?? 'general'
              : (rule.category ?? 'general');
            const vendor = Array.isArray(rule.vendor)
              ? rule.vendor[0] ?? 'common'
              : (rule.vendor ?? 'common');
            console.log(
              `${rule.id.padEnd(18)}${cat.padEnd(22)}${vendor.padEnd(16)}${rule.metadata.level.padEnd(9)}${rule.metadata.obu}`
            );
          }
          console.log('─'.repeat(85));
          console.log(`Total: ${filteredRules.length} rules`);

          if (options.category) {
            console.log(`Filtered by category: ${options.category}`);
          }
        }

        const configFile = findConfigFile(configSearchDir);
        if (configFile && options.listFormat === 'table') {
          console.log(`\nConfig file: ${configFile}`);
        }
        return;
      }

      // Directory scanning mode
      if (options.directory) {
        // Validate directory path
        const dirValidation = validateDirectoryPath(
          options.directory,
          allowedBaseDirs
        );
        if (!dirValidation.valid) {
          if (dirValidation.error?.includes('outside allowed directories')) {
            console.error(
              `Error: Directory is outside project directory: ${options.directory}`
            );
            console.error(`Hint: Use --allow-external to bypass this check`);
          } else {
            console.error(`Error: ${dirValidation.error}`);
          }
          process.exit(2);
        }

        const canonicalDir = dirValidation.canonicalPath!;

        // FR-005: Load directory config from config file
        let directoryConfig: DirectoryConfig | undefined;
        if (options.config !== false) {
          const configPath = options.config ?? findConfigFile(canonicalDir);
          if (configPath) {
            try {
              const config = await loadConfigFile(configPath, allowedBaseDirs);
              directoryConfig = config.directory;
            } catch (err) {
              // Config loading failed - continue without config
              if (options.progress) {
                const msg = err instanceof Error ? err.message : 'Unknown error';
                console.error(`Warning: Failed to load config: ${msg}`);
              }
            }
          }
        }

        // FR-011: Merge CLI options with config file options
        const cliDirOptions = {
          recursive: options.recursive,
          extensions: options.extensions,
          exclude: options.exclude,
          excludePatterns: excludePatterns.length > 0 ? excludePatterns : undefined,
          maxDepth: options.maxDepth,
        };
        const mergedOptions = mergeDirectoryOptions(cliDirOptions, directoryConfig);

        // Scan directory for config files
        if (options.progress) {
          const recursive = mergedOptions.recursive ?? false;
          console.error(
            `Scanning directory: ${canonicalDir}${
              recursive ? ' (recursive)' : ''
            }`
          );
        }

        const scanResult = await scanDirectory(canonicalDir, {
          recursive: mergedOptions.recursive ?? false,
          patterns: options.glob ? [options.glob] : [],
          extensions: mergedOptions.extensions ?? DEFAULT_CONFIG_EXTENSIONS,
          maxFileSize: MAX_CONFIG_SIZE,
          maxDepth: mergedOptions.maxDepth,
          allowedBaseDirs,
          exclude: mergedOptions.exclude ?? [],
          excludePatterns: mergedOptions.excludePatterns ?? [],
        });

        // Report scan errors (non-fatal)
        if (scanResult.errors.length > 0 && options.progress) {
          console.error(`\nWarnings during scan:`);
          for (const err of scanResult.errors) {
            console.error(`  ${err.path}: ${err.message}`);
          }
        }

        if (scanResult.files.length === 0) {
          console.error(
            'No configuration files found in the specified directory.'
          );
          console.error(
            `Searched extensions: ${(
              options.extensions ?? DEFAULT_CONFIG_EXTENSIONS
            ).join(', ')}`
          );
          if (options.glob) {
            console.error(`Glob pattern: ${options.glob}`);
          }
          process.exit(2);
        }

        if (options.progress) {
          console.error(
            `\nFound ${scanResult.files.length} configuration file(s) to scan.\n`
          );
        }

        // AST mode for directory - output ASTs for all files
        if (options.ast) {
          const allAsts: Array<{
            file: string;
            vendor: { id: string; name: string };
            ast: unknown;
          }> = [];

          for (let i = 0; i < scanResult.files.length; i++) {
            const filePath = scanResult.files[i];
            if (!filePath) continue;

            if (options.progress) {
              console.error(
                `[${i + 1}/${scanResult.files.length}] Parsing: ${basename(
                  filePath
                )}`
              );
            }

            try {
              const content = await readFile(filePath, 'utf-8');

              // Resolve vendor per file
              let vendor: VendorSchema;
              if (options.vendor === 'auto') {
                vendor = detectVendor(content);
              } else {
                vendor = getVendor(options.vendor);
              }

              const parser = new SchemaAwareParser({ vendor });
              const nodes = parser.parse(content);

              allAsts.push({
                file: filePath,
                vendor: { id: vendor.id, name: vendor.name },
                ast: nodes,
              });
            } catch (err) {
              const errMsg =
                err instanceof Error ? err.message : 'Unknown error';
              console.error(`  Error parsing ${basename(filePath)}: ${errMsg}`);
              allAsts.push({
                file: filePath,
                vendor: { id: 'unknown', name: 'Unknown' },
                ast: null,
              });
            }
          }

          // Output combined AST results
          const output = {
            summary: {
              filesParsed: allAsts.length,
            },
            files: allAsts,
          };
          console.log(JSON.stringify(output, null, 2));

          if (options.progress) {
            console.error(`\nParsing complete: ${allAsts.length} files`);
          }
          return;
        }

        // Process each file and collect results
        const allFileResults: FileResults[] = [];
        let totalFailures = 0;
        let totalPassed = 0;
        const engine = new RuleEngine();

        for (let i = 0; i < scanResult.files.length; i++) {
          const filePath = scanResult.files[i];
          if (!filePath) continue;

          if (options.progress) {
            console.error(
              `[${i + 1}/${scanResult.files.length}] Scanning: ${basename(
                filePath
              )}`
            );
          }

          try {
            const content = await readFile(filePath, 'utf-8');

            // Resolve vendor per file
            let vendor: VendorSchema;
            if (options.vendor === 'auto') {
              vendor = detectVendor(content);
            } else {
              vendor = getVendor(options.vendor);
            }

            // Filter rules by vendor for this file
            const fileRules = rules.filter((rule) =>
              ruleAppliesToVendor(rule, vendor.id)
            );

            const parser = new SchemaAwareParser({ vendor });
            const nodes = parser.parse(content);
            let results = engine.run(nodes, fileRules);

            // Filter to failures only if quiet mode
            if (options.quiet) {
              results = results.filter((r) => !r.passed);
            }

            // Count results
            const failures = results.filter((r) => !r.passed).length;
            const passed = results.filter((r) => r.passed).length;
            totalFailures += failures;
            totalPassed += passed;

            // Extract IP summary for this file (include subnet network addresses)
            let fileIpSummary = extractIPSummary(content, { includeSubnetNetworks: true });

            // Apply IP filtering if enabled (via CLI option or config)
            if (filterSpecialIps) {
              fileIpSummary = filterIPSummary(fileIpSummary, {
                keepPublic: true,
                keepPrivate: true,
                keepCgnat: true,
                keepLoopback: false,
                keepLinkLocal: false,
                keepMulticast: false,
                keepReserved: false,
                keepUnspecified: false,
                keepBroadcast: false,
                keepDocumentation: false,
              });
            }

            allFileResults.push({
              filePath,
              results,
              vendor: { id: vendor.id, name: vendor.name },
              ipSummary: fileIpSummary,
            });
          } catch (err) {
            // Report per-file errors but continue scanning
            const errMsg = err instanceof Error ? err.message : 'Unknown error';
            console.error(
              `  Error processing ${basename(filePath)}: ${errMsg}`
            );
            allFileResults.push({
              filePath,
              results: [],
            });
          }
        }

        // Output combined results
        if (options.format === 'sarif') {
          const sarifOptions = {
            relativePaths: options.relativePaths,
            baseDir: process.cwd(),
          };
          console.log(
            generateMultiFileSarif(allFileResults, rules, sarifOptions)
          );
        } else {
          // Combined JSON output with summary
          const output = {
            summary: {
              filesScanned: allFileResults.length,
              totalResults: totalFailures + totalPassed,
              failures: totalFailures,
              passed: totalPassed,
            },
            files: allFileResults.map((fr) => ({
              file: fr.filePath,
              vendor: fr.vendor,
              results: enrichResultsWithRuleMetadata(fr.results, rules),
              ipSummary: fr.ipSummary,
            })),
          };
          console.log(JSON.stringify(output, null, 2));
        }

        // Show summary in progress mode
        if (options.progress) {
          console.error(
            `\nScan complete: ${allFileResults.length} files, ${totalFailures} failures, ${totalPassed} passed`
          );
        }

        // Exit with error code if there are failures
        if (totalFailures > 0) {
          process.exit(1);
        }
        return;
      }

      // File mode - Require at least one file for scanning (FR-014)
      if (files.length === 0) {
        program.help();
        return;
      }

      // FR-020: Validate stdin argument usage
      const stdinValidation = validateStdinArgument(files, !!options.directory);
      if (!stdinValidation.valid) {
        console.error(`Error: ${stdinValidation.error}`);
        process.exit(2);
      }

      // FR-017: Stdin mode - read configuration from stdin
      if (isStdinRequested(files)) {
        const stdinResult = await readStdin();

        if (!stdinResult.success) {
          console.error(`Error: ${stdinResult.error}`);
          process.exit(2);
        }

        const content = stdinResult.content!;

        // Resolve vendor (FR-018: auto-detect unless --vendor specified)
        let vendor: VendorSchema;
        if (options.vendor === 'auto') {
          vendor = detectVendor(content);
          if (!options.quiet && !options.ast) {
            console.error(`Detected vendor: ${vendor.name} (${vendor.id})`);
          }
        } else {
          try {
            vendor = getVendor(options.vendor);
          } catch {
            console.error(`Error: Unknown vendor '${options.vendor}'`);
            console.error(`Available vendors: ${getAvailableVendors().join(', ')}, auto`);
            process.exit(2);
          }
        }

        // Resolve rules with detected vendor
        const stdinRules = await resolveRules({
          configPath: options.config,
          noConfig: options.config === false,
          rulesPath: options.rules,
          packPaths: options.pack,
          licenseKey,
          strictPacks: options.strictPacks,
          jsonRulesPaths: options.jsonRules,
          disableIds: options.disable ?? [],
          vendorId: vendor.id,
          cwd: workingDir,
          allowedBaseDirs,
        });

        const parser = new SchemaAwareParser({ vendor });
        const nodes = parser.parse(content);

        if (options.ast) {
          const output = {
            vendor: { id: vendor.id, name: vendor.name },
            ast: nodes,
          };
          console.log(JSON.stringify(output, null, 2));
          return;
        }

        const engine = new RuleEngine();
        let results = engine.run(nodes, stdinRules);

        if (options.quiet) {
          results = results.filter((r) => !r.passed);
        }

        // Extract IP summary from stdin content (include subnet network addresses)
        let stdinIpSummary;
        try {
          stdinIpSummary = extractIPSummary(content, { includeSubnetNetworks: true });

          // Apply IP filtering if enabled (via CLI option or config)
          if (filterSpecialIps) {
            stdinIpSummary = filterIPSummary(stdinIpSummary, {
              keepPublic: true,
              keepPrivate: true,
              keepCgnat: true,
              keepLoopback: false,
              keepLinkLocal: false,
              keepMulticast: false,
              keepReserved: false,
              keepUnspecified: false,
              keepBroadcast: false,
              keepDocumentation: false,
            });
          }
        } catch (error) {
          if (error instanceof InputValidationError) {
            console.error(`Input validation error: ${error.message}`);
            process.exit(2);
          }
          throw error;
        }

        // FR-021: Use <stdin> as filename in output
        if (options.format === 'sarif') {
          const sarifOptions = {
            relativePaths: options.relativePaths,
            baseDir: process.cwd(),
          };
          console.log(generateSarif(results, '<stdin>', stdinRules, sarifOptions, stdinIpSummary));
        } else {
          const output = {
            file: '<stdin>',
            vendor: { id: vendor.id, name: vendor.name },
            results: enrichResultsWithRuleMetadata(results, stdinRules),
            ipSummary: stdinIpSummary,
          };
          console.log(JSON.stringify(output, null, 2));
        }

        const hasFailures = results.some((r) => !r.passed);
        if (hasFailures) {
          process.exit(1);
        }
        return;
      }

      // FR-014/FR-015: Multi-file mode - process all files and aggregate results
      if (files.length > 1) {
        const allFileResults: FileResults[] = [];
        let totalFailures = 0;
        let totalPassed = 0;
        const engine = new RuleEngine();

        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          if (!file) continue;

          // Validate file path
          const fileValidation = validateInputFilePath(
            file,
            MAX_CONFIG_SIZE,
            allowedBaseDirs
          );

          if (!fileValidation.valid) {
            // FR-016: Continue processing remaining files on error
            console.error(`Error processing ${file}: ${fileValidation.error}`);
            allFileResults.push({
              filePath: file,
              results: [],
            });
            continue;
          }

          const filePath = fileValidation.canonicalPath!;

          try {
            const stats = statSync(filePath);
            if (stats.size > MAX_CONFIG_SIZE) {
              console.error(`Error: ${file} exceeds maximum size`);
              allFileResults.push({ filePath: file, results: [] });
              continue;
            }

            const content = await readFile(filePath, 'utf-8');

            // Resolve vendor per file
            let vendor: VendorSchema;
            if (options.vendor === 'auto') {
              vendor = detectVendor(content);
            } else {
              vendor = getVendor(options.vendor);
            }

            // Filter rules by vendor for this file
            const fileRules = rules.filter((rule) =>
              ruleAppliesToVendor(rule, vendor.id)
            );

            const parser = new SchemaAwareParser({ vendor });
            const nodes = parser.parse(content);
            let results = engine.run(nodes, fileRules);

            // Filter to failures only if quiet mode
            if (options.quiet) {
              results = results.filter((r) => !r.passed);
            }

            const failures = results.filter((r) => !r.passed).length;
            const passed = results.filter((r) => r.passed).length;
            totalFailures += failures;
            totalPassed += passed;

            // Extract IP summary for this file (include subnet network addresses)
            let fileIpSummary = extractIPSummary(content, { includeSubnetNetworks: true });

            // Apply IP filtering if enabled (via CLI option or config)
            if (filterSpecialIps) {
              fileIpSummary = filterIPSummary(fileIpSummary, {
                keepPublic: true,
                keepPrivate: true,
                keepCgnat: true,
                keepLoopback: false,
                keepLinkLocal: false,
                keepMulticast: false,
                keepReserved: false,
                keepUnspecified: false,
                keepBroadcast: false,
                keepDocumentation: false,
              });
            }

            allFileResults.push({
              filePath,
              results,
              vendor: { id: vendor.id, name: vendor.name },
              ipSummary: fileIpSummary,
            });
          } catch (err) {
            // FR-016: Continue processing remaining files
            const errMsg = err instanceof Error ? err.message : 'Unknown error';
            console.error(`Error processing ${basename(file)}: ${errMsg}`);
            allFileResults.push({ filePath: file, results: [] });
          }
        }

        // Output combined results (FR-015)
        if (options.format === 'sarif') {
          const sarifOptions = {
            relativePaths: options.relativePaths,
            baseDir: process.cwd(),
          };
          console.log(
            generateMultiFileSarif(allFileResults, rules, sarifOptions)
          );
        } else {
          const output = {
            summary: {
              filesScanned: allFileResults.length,
              totalResults: totalFailures + totalPassed,
              failures: totalFailures,
              passed: totalPassed,
            },
            files: allFileResults.map((fr) => ({
              file: fr.filePath,
              vendor: fr.vendor,
              results: enrichResultsWithRuleMetadata(fr.results, rules),
              ipSummary: fr.ipSummary,
            })),
          };
          console.log(JSON.stringify(output, null, 2));
        }

        if (totalFailures > 0) {
          process.exit(1);
        }
        return;
      }

      // Single file mode
      const file = files[0]!;

      // Validate file path (security: path traversal, symlink resolution, boundary check)
      const fileValidation = validateInputFilePath(
        file,
        MAX_CONFIG_SIZE,
        allowedBaseDirs
      );
      if (!fileValidation.valid) {
        if (fileValidation.error?.includes('outside allowed directories')) {
          console.error(`Error: File is outside project directory: ${file}`);
          console.error(`Hint: Use --allow-external to bypass this check`);
        } else {
          console.error(`Error: ${fileValidation.error}`);
        }
        process.exit(2);
      }

      const filePath = fileValidation.canonicalPath!;

      // Additional file size check (L-2 fix)
      const stats = statSync(filePath);
      if (stats.size > MAX_CONFIG_SIZE) {
        console.error(
          `Error: File exceeds maximum size (${
            MAX_CONFIG_SIZE / 1024 / 1024
          }MB)`
        );
        process.exit(2);
      }

      const content = await readFile(filePath, 'utf-8');

      // Resolve vendor BEFORE rule resolution (so vendor filter is applied)
      let vendor: VendorSchema;
      if (options.vendor === 'auto') {
        vendor = detectVendor(content);
        // Show detected vendor in non-quiet mode
        if (!options.quiet && !options.ast) {
          console.error(`Detected vendor: ${vendor.name} (${vendor.id})`);
        }
      } else {
        try {
          vendor = getVendor(options.vendor);
        } catch (e) {
          console.error(`Error: Unknown vendor '${options.vendor}'`);
          console.error(
            `Available vendors: ${getAvailableVendors().join(', ')}, auto`
          );
          process.exit(2);
        }
      }

      // Now resolve rules with the detected vendor for proper filtering
      const singleFileRules = await resolveRules({
        configPath: options.config,
        noConfig: options.config === false,
        rulesPath: options.rules,
        packPaths: options.pack,
        licenseKey,
        strictPacks: options.strictPacks,
        jsonRulesPaths: options.jsonRules,
        disableIds: options.disable ?? [],
        vendorId: vendor.id, // Now we have the actual detected vendor
        cwd: configSearchDir,
        allowedBaseDirs,
      });

      const parser = new SchemaAwareParser({ vendor });
      const nodes = parser.parse(content);

      if (options.ast) {
        // Include vendor info in AST output
        const output = {
          vendor: {
            id: vendor.id,
            name: vendor.name,
          },
          ast: nodes,
        };
        console.log(JSON.stringify(output, null, 2));
        return;
      }

      const engine = new RuleEngine();
      let results = engine.run(nodes, singleFileRules);

      // Filter to failures only if quiet mode
      if (options.quiet) {
        results = results.filter((r) => !r.passed);
      }

      // Extract IP summary from content (include subnet network addresses)
      let ipSummary = extractIPSummary(content, { includeSubnetNetworks: true });

      // Apply IP filtering if enabled (via CLI option or config)
      if (filterSpecialIps) {
        ipSummary = filterIPSummary(ipSummary, {
          keepPublic: true,
          keepPrivate: true,
          keepCgnat: true,
          keepLoopback: false,
          keepLinkLocal: false,
          keepMulticast: false,
          keepReserved: false,
          keepUnspecified: false,
          keepBroadcast: false,
          keepDocumentation: false,
        });
      }

      // Output results based on format
      if (options.format === 'sarif') {
        const sarifOptions = {
          relativePaths: options.relativePaths,
          baseDir: process.cwd(),
        };
        console.log(
          generateSarif(results, filePath, singleFileRules, sarifOptions, ipSummary)
        );
      } else {
        // Include vendor info and IP summary in JSON output
        const output = {
          vendor: {
            id: vendor.id,
            name: vendor.name,
          },
          results: enrichResultsWithRuleMetadata(results, singleFileRules),
          ipSummary,
        };
        console.log(JSON.stringify(output, null, 2));
      }

      // Exit with error code if there are failures
      const hasFailures = results.some((r) => !r.passed);
      if (hasFailures) {
        process.exit(1);
      }
    } catch (error) {
      // Structured error handling (L-1 fix)
      if (error instanceof SentriflowError) {
        console.error(`Error: ${error.toUserMessage()}`);
      } else if (error instanceof InputValidationError) {
        // T013/T014: Handle size limit and format validation errors
        console.error(`Input validation error: ${error.message}`);
      } else {
        console.error('Error: An unexpected error occurred');
      }
      process.exit(2);
    }
  });

/**
 * Extension hook for @sentriflow/licensing commercial package.
 *
 * This is part of SentriFlow's Open Core model (see README.md).
 *
 * - OSS users: This silently does nothing if @sentriflow/licensing is not installed.
 *   The CLI works fully without it.
 * - Commercial users: This adds 'activate', 'update', 'offline', and 'license' commands
 *   for managing cloud-based rule packs.
 *
 * The dynamic import prevents any hard dependency on the commercial package.
 */
async function loadLicensingExtension(): Promise<void> {
  try {
    // Dynamic import - will fail if @sentriflow/licensing is not installed
    // Use variable to avoid TypeScript static analysis error for optional package
    const licensingModulePath = '@sentriflow/licensing/cli';
    const licensing = await import(/* @vite-ignore */ licensingModulePath) as {
      registerCommands?: (program: unknown) => void;
    };

    // Register licensing commands with the CLI
    if (licensing.registerCommands) {
      licensing.registerCommands(program);
    }
  } catch {
    // @sentriflow/licensing not installed - running in OSS mode
    // This is expected for open-source users
  }
}

// Load licensing extension (if available) before parsing
loadLicensingExtension().finally(() => {
  program.parse();
});

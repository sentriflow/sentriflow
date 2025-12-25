// packages/cli/src/sarif.ts

declare const __VERSION__: string;

import type { RuleResult, IRule, IPSummary, Tag } from '@sentriflow/core';
import { relative } from 'path';

/**
 * SARIF rule definition with SEC-007 security metadata support.
 */
interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
  helpUri?: string;
  /** SEC-007: CWE taxonomy relationships */
  relationships?: Array<{
    target: { id: string; toolComponent: { name: string } };
    kinds: string[];
  }>;
  /** SEC-007: Additional properties for security metadata */
  properties?: {
    'security-severity'?: string;
    'cvss-vector'?: string;
    tags?: string[];
  };
}

/**
 * Options for SARIF generation.
 */
export interface SarifOptions {
  /** Use relative paths instead of absolute paths (L-3 fix) */
  relativePaths?: boolean;
  /** Base directory for relative path calculation */
  baseDir?: string;
}

/**
 * Results for a single file in multi-file scanning.
 */
export interface FileResults {
  filePath: string;
  results: RuleResult[];
  vendor?: { id: string; name: string };
  /** IP/subnet summary extracted from the file */
  ipSummary?: IPSummary;
}

/**
 * Generates a SARIF report from the given rule results.
 *
 * @param results The array of RuleResult objects.
 * @param filePath The path to the scanned file.
 * @param rules Optional array of rules to include metadata in report.
 * @param options Optional SARIF generation options.
 * @param ipSummary Optional IP/subnet summary to include in properties.
 * @returns A string containing the JSON-formatted SARIF report.
 */
export function generateSarif(
  results: RuleResult[],
  filePath: string,
  rules?: IRule[],
  options: SarifOptions = {},
  ipSummary?: IPSummary
): string {
  // Determine the URI to use in the report (L-3 fix: path disclosure)
  const fileUri = options.relativePaths
    ? relative(options.baseDir ?? process.cwd(), filePath)
    : filePath;
  const sarifResults = results.map((result) => {
    return {
      ruleId: result.ruleId,
      level: result.level === 'info' ? 'note' : result.level,
      message: {
        text: result.message,
      },
      locations: result.loc
        ? [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: fileUri, // Use relative or absolute based on options
                },
                region: {
                  startLine: result.loc.startLine + 1, // SARIF is 1-based
                  endLine: result.loc.endLine + 1,
                },
              },
            },
          ]
        : [],
    };
  });

  // Build rule definitions from provided rules
  // SEC-007: Include security metadata (CWE, CVSS) when available
  const sarifRules: SarifRule[] =
    rules?.map((rule) => {
      const base: SarifRule = {
        id: rule.id,
        name: rule.id,
        shortDescription: { text: rule.metadata.remediation ?? rule.id },
        defaultConfiguration: {
          level: rule.metadata.level === 'info' ? 'note' : rule.metadata.level,
        },
      };

      const secMeta = rule.metadata.security;

      // SEC-007: Add CWE relationships if present
      if (secMeta?.cwe && secMeta.cwe.length > 0) {
        base.relationships = secMeta.cwe.map((cweId) => ({
          target: { id: cweId, toolComponent: { name: 'CWE' } },
          kinds: ['superset'],
        }));
      }

      // SEC-007: Add CVSS and tags if present
      const hasCvss = secMeta?.cvssScore !== undefined || secMeta?.cvssVector;
      const hasTags = rule.metadata.tags && rule.metadata.tags.length > 0;

      if (hasCvss || hasTags) {
        base.properties = {};
        if (secMeta?.cvssScore !== undefined) {
          base.properties['security-severity'] = String(secMeta.cvssScore);
        }
        if (secMeta?.cvssVector) {
          base.properties['cvss-vector'] = secMeta.cvssVector;
        }
        if (hasTags) {
          base.properties.tags = rule.metadata.tags!.map((t) => t.label);
        }
      }

      return base;
    }) ?? [];

  // SEC-007: Add CWE taxonomy reference if any rules have CWE mappings
  const hasCweRelationships = sarifRules.some(
    (r) => r.relationships && r.relationships.length > 0
  );

  const report = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentriflow',
            version: __VERSION__,
            informationUri: 'https://github.com/sentriflow/sentriflow',
            rules: sarifRules,
            // SEC-007: Include CWE taxonomy when rules reference it
            ...(hasCweRelationships && {
              supportedTaxonomies: [
                {
                  name: 'CWE',
                  index: 0,
                  guid: '1A0F2A4E-3B93-4C4E-8CC7-9A4E3A5B9A3A',
                },
              ],
            }),
          },
        },
        // SEC-007: Include CWE taxonomy definition when needed
        ...(hasCweRelationships && {
          taxonomies: [
            {
              name: 'CWE',
              version: '4.13',
              informationUri:
                'https://cwe.mitre.org/data/published/cwe_v4.13.pdf',
              organization: 'MITRE',
              shortDescription: { text: 'Common Weakness Enumeration' },
            },
          ],
        }),
        results: sarifResults,
        // Include IP summary in properties if available
        ...(ipSummary && {
          properties: {
            ipSummary,
          },
        }),
      },
    ],
  };

  return JSON.stringify(report, null, 2);
}

/**
 * Aggregates multiple IPSummary objects into a single deduplicated summary.
 */
function aggregateIPSummaries(summaries: IPSummary[]): IPSummary | undefined {
  if (summaries.length === 0) return undefined;

  // Use Sets for deduplication
  const ipv4Set = new Set<string>();
  const ipv6Set = new Set<string>();
  const ipv4SubnetSet = new Set<string>();
  const ipv6SubnetSet = new Set<string>();

  for (const summary of summaries) {
    for (const ip of summary.ipv4Addresses) ipv4Set.add(ip);
    for (const ip of summary.ipv6Addresses) ipv6Set.add(ip);
    for (const subnet of summary.ipv4Subnets) ipv4SubnetSet.add(subnet);
    for (const subnet of summary.ipv6Subnets) ipv6SubnetSet.add(subnet);
  }

  const ipv4Addresses = [...ipv4Set].sort((a, b) => {
    const aParts = a.split('.').map(Number);
    const bParts = b.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if ((aParts[i] ?? 0) !== (bParts[i] ?? 0)) {
        return (aParts[i] ?? 0) - (bParts[i] ?? 0);
      }
    }
    return 0;
  });

  const ipv6Addresses = [...ipv6Set].sort();
  const ipv4Subnets = [...ipv4SubnetSet].sort();
  const ipv6Subnets = [...ipv6SubnetSet].sort();

  return {
    ipv4Addresses,
    ipv6Addresses,
    ipv4Subnets,
    ipv6Subnets,
    counts: {
      ipv4: ipv4Addresses.length,
      ipv6: ipv6Addresses.length,
      ipv4Subnets: ipv4Subnets.length,
      ipv6Subnets: ipv6Subnets.length,
      total:
        ipv4Addresses.length +
        ipv6Addresses.length +
        ipv4Subnets.length +
        ipv6Subnets.length,
    },
  };
}

/**
 * Generates a combined SARIF report from multiple file results.
 *
 * @param fileResults Array of file results to include in the report.
 * @param rules Optional array of rules to include metadata in report.
 * @param options Optional SARIF generation options.
 * @returns A string containing the JSON-formatted SARIF report.
 */
export function generateMultiFileSarif(
  fileResults: FileResults[],
  rules?: IRule[],
  options: SarifOptions = {}
): string {
  // Aggregate IP summaries from all files
  const aggregatedIpSummary = aggregateIPSummaries(
    fileResults.map((fr) => fr.ipSummary).filter((s): s is IPSummary => !!s)
  );

  // Aggregate all results from all files
  const allSarifResults = fileResults.flatMap(({ filePath, results }) => {
    const fileUri = options.relativePaths
      ? relative(options.baseDir ?? process.cwd(), filePath)
      : filePath;

    return results.map((result) => ({
      ruleId: result.ruleId,
      level: result.level === 'info' ? 'note' : result.level,
      message: {
        text: result.message,
      },
      locations: result.loc
        ? [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: fileUri,
                },
                region: {
                  startLine: result.loc.startLine + 1, // SARIF is 1-based
                  endLine: result.loc.endLine + 1,
                },
              },
            },
          ]
        : [],
    }));
  });

  // Build rule definitions from provided rules
  // SEC-007: Include security metadata (CWE, CVSS) when available
  const sarifRules: SarifRule[] =
    rules?.map((rule) => {
      const base: SarifRule = {
        id: rule.id,
        name: rule.id,
        shortDescription: { text: rule.metadata.remediation ?? rule.id },
        defaultConfiguration: {
          level: rule.metadata.level === 'info' ? 'note' : rule.metadata.level,
        },
      };

      const secMeta = rule.metadata.security;

      // SEC-007: Add CWE relationships if present
      if (secMeta?.cwe && secMeta.cwe.length > 0) {
        base.relationships = secMeta.cwe.map((cweId) => ({
          target: { id: cweId, toolComponent: { name: 'CWE' } },
          kinds: ['superset'],
        }));
      }

      // SEC-007: Add CVSS and tags if present
      const hasCvss = secMeta?.cvssScore !== undefined || secMeta?.cvssVector;
      const hasTags = rule.metadata.tags && rule.metadata.tags.length > 0;

      if (hasCvss || hasTags) {
        base.properties = {};
        if (secMeta?.cvssScore !== undefined) {
          base.properties['security-severity'] = String(secMeta.cvssScore);
        }
        if (secMeta?.cvssVector) {
          base.properties['cvss-vector'] = secMeta.cvssVector;
        }
        if (hasTags) {
          base.properties.tags = rule.metadata.tags!.map((t) => t.label);
        }
      }

      return base;
    }) ?? [];

  // SEC-007: Add CWE taxonomy reference if any rules have CWE mappings
  const hasCweRelationships = sarifRules.some(
    (r) => r.relationships && r.relationships.length > 0
  );

  // Collect all unique artifact URIs for the artifacts array
  const artifactUris = [
    ...new Set(
      fileResults.map(({ filePath }) =>
        options.relativePaths
          ? relative(options.baseDir ?? process.cwd(), filePath)
          : filePath
      )
    ),
  ];

  const report = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentriflow',
            version: __VERSION__,
            informationUri: 'https://github.com/sentriflow/sentriflow',
            rules: sarifRules,
            // SEC-007: Include CWE taxonomy when rules reference it
            ...(hasCweRelationships && {
              supportedTaxonomies: [
                {
                  name: 'CWE',
                  index: 0,
                  guid: '1A0F2A4E-3B93-4C4E-8CC7-9A4E3A5B9A3A',
                },
              ],
            }),
          },
        },
        // Include artifacts array for multi-file reports
        artifacts: artifactUris.map((uri) => ({
          location: { uri },
        })),
        // SEC-007: Include CWE taxonomy definition when needed
        ...(hasCweRelationships && {
          taxonomies: [
            {
              name: 'CWE',
              version: '4.13',
              informationUri:
                'https://cwe.mitre.org/data/published/cwe_v4.13.pdf',
              organization: 'MITRE',
              shortDescription: { text: 'Common Weakness Enumeration' },
            },
          ],
        }),
        results: allSarifResults,
        // Include aggregated IP summary in properties if available
        ...(aggregatedIpSummary && {
          properties: {
            ipSummary: aggregatedIpSummary,
          },
        }),
      },
    ],
  };

  return JSON.stringify(report, null, 2);
}

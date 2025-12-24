/**
 * TR-006: Unit tests for multi-file argument handling
 * Tests: single file, multiple files, empty array, result aggregation
 */
import { describe, it, expect } from 'bun:test';

// Mock types matching CLI output structure
interface FileResultSummary {
  filesScanned: number;
  totalResults: number;
  failures: number;
  passed: number;
}

interface FileResult {
  file: string;
  vendor?: { id: string; name: string };
  results: unknown[];
}

interface MultiFileOutput {
  summary: FileResultSummary;
  files: FileResult[];
}

/**
 * Helper to simulate multi-file argument processing
 * This mimics the CLI's file argument handling logic
 */
function processFileArguments(files: string[]): {
  mode: 'single' | 'multi' | 'none';
  files: string[];
} {
  if (files.length === 0) {
    return { mode: 'none', files: [] };
  }
  if (files.length === 1) {
    return { mode: 'single', files };
  }
  return { mode: 'multi', files };
}

/**
 * Helper to aggregate results from multiple files
 */
function aggregateResults(fileResults: FileResult[]): MultiFileOutput {
  let failures = 0;
  let passed = 0;

  for (const fr of fileResults) {
    for (const result of fr.results as Array<{ passed: boolean }>) {
      if (result.passed) {
        passed++;
      } else {
        failures++;
      }
    }
  }

  return {
    summary: {
      filesScanned: fileResults.length,
      totalResults: failures + passed,
      failures,
      passed,
    },
    files: fileResults,
  };
}

describe('multi-file argument handling', () => {
  describe('file argument modes', () => {
    it('should detect single file mode', () => {
      const result = processFileArguments(['router.cfg']);
      expect(result.mode).toBe('single');
      expect(result.files).toEqual(['router.cfg']);
    });

    it('should detect multi-file mode with 2 files', () => {
      const result = processFileArguments(['router.cfg', 'switch.cfg']);
      expect(result.mode).toBe('multi');
      expect(result.files.length).toBe(2);
    });

    it('should detect multi-file mode with many files', () => {
      const files = ['a.cfg', 'b.cfg', 'c.cfg', 'd.cfg', 'e.cfg'];
      const result = processFileArguments(files);
      expect(result.mode).toBe('multi');
      expect(result.files.length).toBe(5);
    });

    it('should handle no files (none mode)', () => {
      const result = processFileArguments([]);
      expect(result.mode).toBe('none');
      expect(result.files.length).toBe(0);
    });
  });

  describe('result aggregation', () => {
    it('should aggregate results from single file', () => {
      const fileResults: FileResult[] = [
        {
          file: 'router.cfg',
          vendor: { id: 'cisco-ios', name: 'Cisco IOS' },
          results: [
            { passed: true },
            { passed: false },
          ],
        },
      ];

      const output = aggregateResults(fileResults);
      expect(output.summary.filesScanned).toBe(1);
      expect(output.summary.totalResults).toBe(2);
      expect(output.summary.passed).toBe(1);
      expect(output.summary.failures).toBe(1);
    });

    it('should aggregate results from multiple files', () => {
      const fileResults: FileResult[] = [
        {
          file: 'router.cfg',
          results: [{ passed: true }, { passed: true }],
        },
        {
          file: 'switch.cfg',
          results: [{ passed: false }],
        },
        {
          file: 'firewall.cfg',
          results: [{ passed: true }, { passed: false }, { passed: false }],
        },
      ];

      const output = aggregateResults(fileResults);
      expect(output.summary.filesScanned).toBe(3);
      expect(output.summary.totalResults).toBe(6);
      expect(output.summary.passed).toBe(3);
      expect(output.summary.failures).toBe(3);
    });

    it('should handle empty results', () => {
      const fileResults: FileResult[] = [];
      const output = aggregateResults(fileResults);
      expect(output.summary.filesScanned).toBe(0);
      expect(output.summary.totalResults).toBe(0);
    });

    it('should handle files with no results', () => {
      const fileResults: FileResult[] = [
        { file: 'empty.cfg', results: [] },
      ];

      const output = aggregateResults(fileResults);
      expect(output.summary.filesScanned).toBe(1);
      expect(output.summary.totalResults).toBe(0);
    });
  });

  describe('file path handling', () => {
    it('should preserve relative paths', () => {
      const result = processFileArguments(['./configs/router.cfg']);
      expect(result.files[0]).toBe('./configs/router.cfg');
    });

    it('should preserve absolute paths', () => {
      const result = processFileArguments(['/etc/configs/router.cfg']);
      expect(result.files[0]).toBe('/etc/configs/router.cfg');
    });

    it('should handle mixed path types', () => {
      const files = ['router.cfg', './switch.cfg', '/abs/firewall.cfg'];
      const result = processFileArguments(files);
      expect(result.files).toEqual(files);
    });
  });

  describe('edge cases', () => {
    it('should handle duplicate file paths', () => {
      const files = ['router.cfg', 'router.cfg'];
      const result = processFileArguments(files);
      // Duplicates are allowed - CLI doesn't dedupe
      expect(result.files.length).toBe(2);
    });

    it('should handle files with special characters in names', () => {
      const files = ['router[1].cfg', 'switch (backup).cfg'];
      const result = processFileArguments(files);
      expect(result.mode).toBe('multi');
      expect(result.files.length).toBe(2);
    });

    it('should handle files with unicode names', () => {
      const files = ['маршрутизатор.cfg', 'ルーター.cfg'];
      const result = processFileArguments(files);
      expect(result.mode).toBe('multi');
    });
  });
});

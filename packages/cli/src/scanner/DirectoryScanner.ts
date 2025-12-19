// packages/cli/src/scanner/DirectoryScanner.ts

import { readdir, stat } from 'fs/promises';
import { join, resolve, extname } from 'path';
import { realpathSync, existsSync } from 'fs';
import { MAX_CONFIG_SIZE } from '@sentriflow/core';

/**
 * Options for directory scanning.
 */
export interface DirectoryScanOptions {
    /** Scan directories recursively */
    recursive?: boolean;
    /** Glob patterns to match (e.g., '*.txt', '*.cfg') */
    patterns?: string[];
    /** File extensions to include (without dot, e.g., 'txt', 'cfg') */
    extensions?: string[];
    /** Maximum file size to include */
    maxFileSize?: number;
    /** Maximum depth for recursive scanning (default: 100) */
    maxDepth?: number;
    /** Base directories for security boundary check */
    allowedBaseDirs?: string[];
    /** Exclude patterns (glob-like) */
    exclude?: string[];
}

/**
 * Result of a directory scan.
 */
export interface DirectoryScanResult {
    /** Successfully discovered files */
    files: string[];
    /** Errors encountered during scanning */
    errors: ScanError[];
    /** Directories that were scanned */
    scannedDirs: string[];
}

/**
 * Error encountered during scanning.
 */
export interface ScanError {
    path: string;
    message: string;
}

/**
 * Default file extensions for network configuration files.
 */
export const DEFAULT_CONFIG_EXTENSIONS = [
    'txt', 'cfg', 'conf', 'config',
    'ios', 'junos', 'eos', 'nxos',
    'routeros', 'vyos', 'panos',
    'sros', 'vrp', 'exos', 'voss',
];

/**
 * Normalizes path separators for cross-platform comparison.
 */
function normalizeSeparators(p: string): string {
    return p.replace(/\\/g, '/');
}

/**
 * Checks if a path is within allowed directories.
 */
function isWithinBounds(filePath: string, allowedBaseDirs?: string[]): boolean {
    if (!allowedBaseDirs || allowedBaseDirs.length === 0) {
        return true;
    }

    const normalizedPath = normalizeSeparators(filePath);

    return allowedBaseDirs.some(baseDir => {
        try {
            const canonicalBase = realpathSync(resolve(baseDir));
            const normalizedBase = normalizeSeparators(canonicalBase);
            return (
                normalizedPath === normalizedBase ||
                normalizedPath.startsWith(normalizedBase + '/')
            );
        } catch (error) {
            // Log error for debugging (base directory resolution failure)
            const errorType = error instanceof Error ? error.name : 'Unknown';
            if (process.env.DEBUG) {
                console.error(`[DirectoryScanner] Failed to resolve base directory: ${errorType}`, error);
            }
            return false;
        }
    });
}

/**
 * Simple glob pattern matching.
 * Supports: * (any chars), ? (single char), ** (recursive dir match)
 */
function matchesPattern(fileName: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape special regex chars
        .replace(/\*\*/g, '{{GLOBSTAR}}')      // Placeholder for **
        .replace(/\*/g, '[^/]*')               // * matches anything except /
        .replace(/\?/g, '.')                   // ? matches single char
        .replace(/{{GLOBSTAR}}/g, '.*');       // ** matches anything

    const regex = new RegExp(`^${regexPattern}$`, 'i');
    return regex.test(fileName);
}

/**
 * Checks if a file matches any of the given patterns.
 */
function matchesAnyPattern(fileName: string, patterns: string[]): boolean {
    if (patterns.length === 0) return true;
    return patterns.some(pattern => matchesPattern(fileName, pattern));
}

/**
 * Checks if a path matches any exclude pattern.
 */
function isExcluded(relativePath: string, excludePatterns: string[]): boolean {
    if (excludePatterns.length === 0) return false;
    return excludePatterns.some(pattern => matchesPattern(relativePath, pattern));
}

/**
 * Scans a directory for configuration files.
 *
 * @param dirPath - Path to the directory to scan
 * @param options - Scanning options
 * @returns Scan result with discovered files and any errors
 */
export async function scanDirectory(
    dirPath: string,
    options: DirectoryScanOptions = {}
): Promise<DirectoryScanResult> {
    const {
        recursive = false,
        patterns = [],
        extensions = DEFAULT_CONFIG_EXTENSIONS,
        maxFileSize = MAX_CONFIG_SIZE,
        maxDepth = 100,
        allowedBaseDirs,
        exclude = [],
    } = options;

    const result: DirectoryScanResult = {
        files: [],
        errors: [],
        scannedDirs: [],
    };

    // Resolve and validate the directory path
    let canonicalDir: string;
    try {
        canonicalDir = realpathSync(resolve(dirPath));
    } catch {
        result.errors.push({
            path: dirPath,
            message: 'Directory not found or inaccessible',
        });
        return result;
    }

    // Security: Check if directory is within bounds
    if (!isWithinBounds(canonicalDir, allowedBaseDirs)) {
        result.errors.push({
            path: dirPath,
            message: 'Directory is outside allowed directories',
        });
        return result;
    }

    // Internal recursive scan function
    async function scan(currentDir: string, depth: number, basePath: string): Promise<void> {
        if (depth > maxDepth) {
            result.errors.push({
                path: currentDir,
                message: `Maximum scan depth (${maxDepth}) exceeded`,
            });
            return;
        }

        result.scannedDirs.push(currentDir);

        let entries: string[];
        try {
            entries = await readdir(currentDir);
        } catch (error) {
            result.errors.push({
                path: currentDir,
                message: `Failed to read directory: ${error instanceof Error ? error.message : 'Unknown error'}`,
            });
            return;
        }

        for (const entry of entries) {
            const fullPath = join(currentDir, entry);
            const relativePath = join(basePath, entry);

            // Check exclusion patterns
            if (isExcluded(relativePath, exclude)) {
                continue;
            }

            let stats;
            try {
                stats = await stat(fullPath);
            } catch {
                result.errors.push({
                    path: fullPath,
                    message: 'Failed to stat file',
                });
                continue;
            }

            if (stats.isDirectory()) {
                // Recursively scan subdirectories if enabled
                if (recursive) {
                    await scan(fullPath, depth + 1, relativePath);
                }
            } else if (stats.isFile()) {
                // Check file extension
                const ext = extname(entry).toLowerCase().slice(1); // Remove leading dot
                const hasValidExtension = extensions.length === 0 || extensions.includes(ext);

                // Check pattern match
                const matchesPatterns = matchesAnyPattern(entry, patterns);

                // Check file size
                const withinSizeLimit = stats.size <= maxFileSize;

                if (hasValidExtension && matchesPatterns && withinSizeLimit) {
                    // Security: Verify file is within bounds (handles symlinks)
                    try {
                        const canonicalFile = realpathSync(fullPath);
                        if (isWithinBounds(canonicalFile, allowedBaseDirs)) {
                            result.files.push(canonicalFile);
                        } else {
                            result.errors.push({
                                path: fullPath,
                                message: 'File symlink points outside allowed directories',
                            });
                        }
                    } catch {
                        result.errors.push({
                            path: fullPath,
                            message: 'Failed to resolve file path',
                        });
                    }
                } else if (!withinSizeLimit) {
                    result.errors.push({
                        path: fullPath,
                        message: `File exceeds size limit (${stats.size} > ${maxFileSize})`,
                    });
                }
            }
        }
    }

    await scan(canonicalDir, 0, '');

    return result;
}

/**
 * Validates that a path is a directory.
 */
export function validateDirectoryPath(
    dirPath: string,
    allowedBaseDirs?: string[]
): { valid: boolean; canonicalPath?: string; error?: string } {
    try {
        // Block UNC paths
        if (dirPath.startsWith('\\\\') || dirPath.startsWith('//')) {
            return {
                valid: false,
                error: 'Network (UNC) paths are not allowed',
            };
        }

        const absolutePath = resolve(dirPath);

        // Check if exists
        if (!existsSync(absolutePath)) {
            return { valid: false, error: 'Directory not found' };
        }

        // Resolve symlinks
        let canonicalPath: string;
        try {
            canonicalPath = realpathSync(absolutePath);
        } catch {
            return { valid: false, error: 'Failed to resolve path' };
        }

        // Verify it's a directory
        const { statSync } = require('fs');
        const stats = statSync(canonicalPath);
        if (!stats.isDirectory()) {
            return { valid: false, error: 'Path is not a directory' };
        }

        // Security: Check bounds
        if (!isWithinBounds(canonicalPath, allowedBaseDirs)) {
            return {
                valid: false,
                error: 'Directory is outside allowed directories',
            };
        }

        return { valid: true, canonicalPath };
    } catch {
        return { valid: false, error: 'Path validation failed' };
    }
}

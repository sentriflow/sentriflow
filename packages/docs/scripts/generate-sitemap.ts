#!/usr/bin/env bun
/**
 * Generate sitemap.xml from MDX content files.
 * Outputs to public/sitemap.xml for inclusion in the static export.
 *
 * Usage:
 *   bun run scripts/generate-sitemap.ts
 *   bun run generate-sitemap
 */

import { readdirSync, statSync, writeFileSync } from 'fs';
import { join, dirname, relative, extname, basename } from 'path';

const SITE_URL = 'https://docs.sentriflow.com.au';
const CONTENT_DIR = join(dirname(import.meta.path), '..', 'content');
const OUTPUT_PATH = join(dirname(import.meta.path), '..', 'public', 'sitemap.xml');

/**
 * Recursively collect all MDX files from the content directory.
 */
function collectMdxFiles(dir: string): string[] {
  const files: string[] = [];

  for (const entry of readdirSync(dir)) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      files.push(...collectMdxFiles(fullPath));
    } else if (extname(entry) === '.mdx') {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Convert a content file path to a URL path.
 * e.g. content/getting-started/installation.mdx -> /getting-started/installation/
 */
function fileToUrlPath(filePath: string): string {
  let rel = relative(CONTENT_DIR, filePath);
  // Remove .mdx extension
  rel = rel.replace(/\.mdx$/, '');
  // index files map to directory root
  if (basename(rel) === 'index') {
    rel = dirname(rel);
    if (rel === '.') return '/';
  }
  return `/${rel}/`;
}

/**
 * Assign priority based on URL depth and importance.
 */
function getPriority(urlPath: string): string {
  if (urlPath === '/') return '1.0';
  if (urlPath.startsWith('/getting-started/')) return '0.9';
  if (urlPath.startsWith('/guides/')) return '0.9';
  if (urlPath.startsWith('/rules/')) return '0.8';
  if (urlPath.startsWith('/cli/')) return '0.7';
  if (urlPath.startsWith('/integrations/')) return '0.7';
  return '0.5';
}

function generateSitemap(): void {
  const mdxFiles = collectMdxFiles(CONTENT_DIR);
  const today = new Date().toISOString().split('T')[0];

  const urls = mdxFiles
    .map(fileToUrlPath)
    .sort()
    .map((urlPath) => {
      const priority = getPriority(urlPath);
      return `  <url>
    <loc>${SITE_URL}${urlPath}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>${priority}</priority>
  </url>`;
    });

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join('\n')}
</urlset>
`;

  writeFileSync(OUTPUT_PATH, sitemap);
  console.log(`Generated sitemap with ${urls.length} URLs to ${OUTPUT_PATH}`);
}

generateSitemap();

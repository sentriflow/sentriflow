// ESLint 9.x flat config for SentriFlow monorepo
// Constitution compliance: Technology Stack requirement
// Gradual adoption: Using recommended config with warnings for existing issues

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // T004: Ignore patterns for build artifacts and dependencies
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/coverage/**",
      "**/*.d.ts",
    ],
  },
  {
    // Node.js scripts - enable Node globals
    files: ["**/*.mjs", "**/scripts/**/*.js"],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },
  {
    // TypeScript-specific rules with gradual adoption
    files: ["**/*.ts", "**/*.tsx"],
    rules: {
      // Relax rules for gradual adoption - upgrade to error over time
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      // Allow require() for dynamic imports (used in DirectoryScanner.ts)
      "@typescript-eslint/no-require-imports": "warn",
      // Gradual adoption: existing codebase issues - TODO: upgrade to error
      "no-control-regex": "warn", // Control chars in parser regex patterns
      "no-useless-escape": "warn", // Escape sequences in regex
      "no-empty": ["warn", { allowEmptyCatch: true }], // Empty catch blocks
      "prefer-const": "warn", // let vs const
    },
  }
);

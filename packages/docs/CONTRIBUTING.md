# Contributing to SentriFlow Documentation

Thank you for your interest in contributing to SentriFlow documentation! This guide will help you get started.

## Prerequisites

- [Node.js](https://nodejs.org/) 18.x or higher
- [Bun](https://bun.sh/) (recommended) or npm
- Basic knowledge of Markdown and MDX

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/sentriflow/sentriflow.git
cd sentriflow/packages/docs
```

### 2. Install Dependencies

```bash
bun install
```

### 3. Start Development Server

```bash
bun run dev
```

Open [http://localhost:3000](http://localhost:3000) to preview your changes.

## Documentation Structure

```
packages/docs/
├── app/                    # Next.js App Router
│   └── layout.tsx          # Root layout with Nextra
├── content/                # MDX documentation files
│   ├── index.mdx           # Homepage
│   ├── getting-started/    # Getting started guides
│   ├── cli/                # CLI reference
│   ├── cicd/               # CI/CD integration guides
│   ├── rules/              # Rule catalog
│   ├── authoring/          # Rule authoring guides
│   ├── vscode/             # VS Code extension docs
│   └── api/                # API reference
├── components/             # React components
├── styles/                 # Global CSS styles
└── public/                 # Static assets
```

## Writing Documentation

### Creating a New Page

1. Create a new `.mdx` file in the appropriate directory under `content/`
2. Add frontmatter at the top:

```mdx
---
title: Your Page Title
description: A brief description for SEO
---

# Your Page Title

Content goes here...
```

3. Update the `_meta.json` file in the same directory to add navigation:

```json
{
  "existing-page": "Existing Page",
  "your-new-page": "Your New Page"
}
```

### MDX Components

Use Nextra's built-in components for enhanced content:

```mdx
import { Callout, Tabs, Steps } from 'nextra/components'

<Callout type="info">
  This is an informational callout.
</Callout>

<Callout type="warning">
  This is a warning callout.
</Callout>

<Tabs items={['npm', 'yarn', 'pnpm', 'bun']}>
  <Tabs.Tab>npm install @sentriflow/core</Tabs.Tab>
  <Tabs.Tab>yarn add @sentriflow/core</Tabs.Tab>
  <Tabs.Tab>pnpm add @sentriflow/core</Tabs.Tab>
  <Tabs.Tab>bun add @sentriflow/core</Tabs.Tab>
</Tabs>

<Steps>
### Step 1
Do something first.

### Step 2
Then do something else.
</Steps>
```

### Code Blocks

Code blocks support syntax highlighting and copy buttons:

````mdx
```typescript
// TypeScript code with syntax highlighting
import { parse } from '@sentriflow/core';

const ast = parse(config, 'cisco-ios');
```

```bash filename="Terminal"
# Shell commands with filename
sentriflow check router.conf --format sarif
```
````

### Custom Components

Use SentriFlow-specific components:

```mdx
import { VendorBadge } from '@/components/VendorBadge'
import { SeverityBadge } from '@/components/SeverityBadge'

<VendorBadge vendor="cisco-ios" />
<SeverityBadge severity="error" />
```

## Style Guidelines

### Writing Style

- Use clear, concise language
- Write in second person ("you") when addressing users
- Use active voice
- Include practical examples
- Test all code examples before committing

### Formatting

- Use sentence case for headings
- Keep paragraphs short (3-5 sentences)
- Use bullet points for lists
- Add alt text to images
- Use descriptive link text (not "click here")

### Code Examples

- Provide complete, working examples
- Include comments explaining complex code
- Show expected output where helpful
- Test all code snippets

## Building and Testing

### Build for Production

```bash
bun run build
```

This generates a static site in the `out/` directory.

### Type Checking

```bash
bun run type-check
```

### Preview Production Build

```bash
bun run start
```

## Submitting Changes

### 1. Create a Branch

```bash
git checkout -b docs/your-feature-name
```

### 2. Make Your Changes

Edit files, add new content, fix issues.

### 3. Test Locally

```bash
bun run dev
# Verify changes look correct
bun run build
# Ensure build succeeds
```

### 4. Commit Your Changes

Follow the commit message format:

```bash
git commit -m "docs: add example for custom rules"
```

Commit types:
- `docs:` - Documentation changes
- `fix:` - Bug fixes in docs
- `feat:` - New documentation features
- `style:` - Formatting, styling changes

### 5. Push and Create Pull Request

```bash
git push origin docs/your-feature-name
```

Then create a Pull Request on GitHub.

## Need Help?

- Check existing [documentation](https://docs.sentriflow.com.au)
- Open an [issue](https://github.com/sentriflow/sentriflow/issues)
- Join the discussion on GitHub

## License

By contributing, you agree that your contributions will be licensed under the same [MIT License](https://github.com/sentriflow/sentriflow/blob/main/LICENSE) that covers the project.

# Contributing to packsafe

Thank you for contributing to `packsafe`!

## Development Setup

```bash
git clone https://github.com/packsafe/packsafe.git
cd packsafe
npm ci --ignore-scripts
```

## Checks

Run all checks locally before opening a pull request:

```bash
npm run lint
npm run typecheck
npm run build:types
npm test
npm run test:coverage
node bin/packsafe.js
```

## Design Principles

- **Zero runtime dependencies**: Node.js built-ins only.
- **No shell execution**: Never use `exec` or `shell: true`.
- **Linear-time regexes**: Avoid nested quantifiers and test pathological inputs.
- **Beginner-maintainable**: Keep modules small, well-typed with JSDoc, and clearly commented.

# Security Review — PackSafe

This document records the self-audit of `packsafe` against its own threat model.

## Threat Model & Controls

| Control | Implementation | Verification |
| :--- | :--- | :--- |
| **No shell execution (`exec` / `shell: true`)** | All subprocess calls (`npm`, `git`) use `execFile` with argument arrays, `shell: false`, explicit `timeout`, and `maxBuffer`. | Verified in `src/publish-set.js` and `src/identity.js`; ESLint + code review. |
| **Windows `.cmd` hardening** | Resolves `npm_execpath` or `npm-cli.js` and executes via `process.execPath` (`node`) without `shell: true`. | Unit-tested in `test/unit/publish-set.test.js`. |
| **Lifecycle scripts disabled by default** | Passes `--ignore-scripts` to `npm pack --dry-run --json` unless `--run-scripts` is explicitly passed (which emits a stderr warning). | Tested with a malicious `prepack` script in `test/unit/publish-set.test.js`. |
| **Path traversal & symlink escape protection** | `resolveSafePackagePath` rejects empty paths, NUL bytes, absolute paths, `..` segments, and symlinks resolving outside `packageRoot`. | Unit-tested in `test/unit/paths-redact.test.js`. |
| **Read-only & offline** | Never modifies scanned packages, never evaluates scanned JS, never makes network requests. | Verified across `src/`. |
| **Secret redaction & relative paths** | `redactSecret` outputs at most 4 prefix chars + length; all reporters emit relative POSIX paths only. | Verified in `test/unit/paths-redact.test.js` and `test/e2e/tarball-smoke.test.js`. |
| **Prototype pollution resistance** | `validateConfig` rejects `__proto__`, `constructor`, `prototype`, and unknown keys; uses `Object.prototype.hasOwnProperty.call`. | Unit-tested in `test/unit/config-reporters-cli.test.js`. |
| **ReDoS resistance** | All regexes in `src/rules/` use bounded quantifiers without nested repetition; `PS002` uses `String.prototype.indexOf`. | Tested with pathological inputs in `test/unit/fuzz.test.js`. |
| **Supply chain** | Zero runtime dependencies, `package.json` `"files"` allowlist, `npm audit` clean, GitHub Actions pinned to 40-char commit SHAs with least-privilege `permissions:`, CodeQL, Dependabot, `--provenance` release workflow. | Verified in `.github/` and `package.json`. |

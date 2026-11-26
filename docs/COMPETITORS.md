# Competitor & Ecosystem Landscape

Before building `packsafe`, we evaluated existing tools in the npm, security, and linting ecosystems to verify whether any existing package already solves the pre-publish personal/internal data leak problem for npm tarballs.

## Evaluated Tools

| Tool | URL | What it does | What it does NOT do |
| :--- | :--- | :--- | :--- |
| **publint** | [https://publint.dev](https://publint.dev) / [github.com/publint/publint](https://github.com/publint/publint) | Lints npm packages for `package.json` packaging errors (`exports`, `main`, `module`, `types`, ESM/CJS mismatches). | Does not scan file contents for leaked usernames, home paths, secrets, sourcemaps, or internal URLs. |
| **npm-packlist** | [github.com/npm/npm-packlist](https://github.com/npm/npm-packlist) | Computes the exact list of files `npm pack` / `npm publish` will include based on `files`, `.npmignore`, and `.gitignore`. | Only lists filenames; does not inspect file contents, parse sourcemaps, or detect secrets/identity leaks. |
| **secretlint** | [github.com/secretlint/secretlint](https://github.com/secretlint/secretlint) | Pluggable linter that scans source files or stdin for hardcoded credentials, API keys, and tokens. | Does not restrict scanning to npm's exact publish set (meaning build artifacts in `dist/` ignored by git are missed unless explicitly targeted), does not auto-detect current machine identity, and does not parse sourcemaps or check package size/internal URLs. |
| **gitleaks** | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | Fast Go binary for scanning git repositories and commit history for secrets using regexes and entropy. | Focuses on git history rather than the npm tarball publish set (which often contains un-tracked `dist/` bundles and `.map` files); does not detect local OS usernames, home directory paths, or machine hostnames. |
| **trufflehog** | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | Scans repositories, filesystems, and buckets for secrets and actively verifies live credentials via network API calls. | Makes network calls for verification, requires a Go binary, and does not audit npm tarball metadata, OS identity leaks, or sourcemap path disclosures. |
| **push-guard** | [npmjs.com/package/push-guard](https://www.npmjs.com/package/push-guard) | Git pre-push hook that blocks pushing environment variables and secrets to git remotes. | Operates on git pushes rather than `npm publish` tarballs; does not inspect built artifacts, sourcemaps, or machine identity. |
| **leakcheck** | [github.com/qwertymuzaffar/leakcheck](https://github.com/qwertymuzaffar/leakcheck) | TypeScript library for detecting data leakage, drift, and schema contracts in ML datasets. | Unrelated to npm package publishing or code/secret scanning. |
| **ls-engines** | [github.com/ljharb/ls-engines](https://github.com/ljharb/ls-engines) | Checks whether a dependency graph satisfies its declared `engines` constraints. | Does not inspect published file contents or security/privacy leaks. |
| **Sourcemap analyzers** (e.g. `source-map-explorer`) | [npmjs.com](https://www.npmjs.com) | Visualize bundle composition and byte sizes from `.map` files. | Do not flag absolute local paths (`C:\Users\...`, `/Users/...`, `/home/...`) or scan `sourcesContent` for secrets and machine identity. |

## Differentiation

No existing tool combines npm's exact publish-set resolution (`npm pack --dry-run --json --ignore-scripts`) with automatic local machine-identity awareness (OS username, home directory, hostname, and git `user.name`/`user.email`), deep `.map` sourcemap inspection (`sources`, `sourceRoot`, and decoded `sourcesContent`), and zero-dependency offline execution. Git-centric secret scanners (`gitleaks`, `trufflehog`, `secretlint`) miss the most common npm leak vector: untracked build outputs (`dist/`, `build/`, `*.map`) that are `.gitignore`d in git yet shipped to npm, where bundlers and compilers routinely embed local absolute paths, usernames, internal registry URLs, and `.env` values. `packsafe` fills this specific gap as a zero-dependency, offline `prepublishOnly` gate.

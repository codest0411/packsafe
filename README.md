# packsafe

A zero-dependency, offline pre-publish security and privacy gate for npm packages.

`packsafe` audits the **exact set of files `npm publish` would ship** (via `npm pack --dry-run --json --ignore-scripts`) and checks them against your current machine identity, local absolute paths, embedded sourcemaps, hardcoded secrets, risky files, internal URLs, package size thresholds, and un-allowlisted emails.

## The problem

Build tools, TypeScript sourcemaps, and `.npmignore` mistakes routinely bake personal or internal data into npm tarballs—even when your git repository is completely clean.

**Before `packsafe` (`npm publish` ships `dist/index.js.map` and `.env.local`):**

```text
dist/index.js.map -> "sources": ["C:\\Users\\alexsmith\\work\\secret-project\\src\\index.ts"]
dist/index.js     -> const apiUrl = "https://auth.corp.internal/v1";
.env.local        -> NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**After `packsafe` (`prepublishOnly` blocks the publish):**

```text
ERROR [PS004] dist/index.js.map
      Sourcemap sources[0] contains an absolute local path (C:\Users\alexsmith\work\secret-project\src\index.ts)
ERROR [PS005] .env.local
      Risky file in publish set: Environment file (.env*) (.env.local)
ERROR [PS003] .env.local:1:11
      npm access token detected (npm_...[redacted len=40])
WARN  [PS006] dist/index.js:1:16
      Internal hostname URL detected (https://auth.corp.internal/v1)

FAILED — 3 error(s), 1 warning(s), 0 info (fail-on: error)
```

## Quick start

Run against the current directory without installing:

```bash
npx packsafe
```

Or add it as a `prepublishOnly` gate in `package.json`:

```json
{
  "devDependencies": {
    "packsafe": "^0.1.0"
  },
  "scripts": {
    "prepublishOnly": "packsafe"
  }
}
```

## CLI options

```text
packsafe [path] [options]

  --format <fmt>      human (default), json, github, sarif
  --fail-on <level>   error (default), warn, info, none
  --config <file>     Path to .packsaferc.json
  --run-scripts       Allow npm pack lifecycle scripts (OFF by default)
  --no-color          Disable ANSI colors in human output
  -h, --help          Show help
  -v, --version       Show version
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage, configuration, or runtime error.

## Rules

| Rule | Severity | What it catches | Example |
| :--- | :--- | :--- | :--- |
| `PS001` | `error` | Absolute home paths (`/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `C:\\Users\\<user>`, `file://`) | `const p = "/Users/alexsmith/app";` |
| `PS002` | `error` | Current machine identity (OS username, hostname, homedir, git `user.name`/`user.email`) and `denyWords` | `// built by alexsmith on laptop-42` |
| `PS003` | `error` | Private keys, npm/GitHub/AWS/Slack tokens, `_authToken=`, hardcoded password/secret assignments (redacted) | `NPM_TOKEN=npm_...` |
| `PS004` | `error`/`warn`/`info` | `.map` sourcemaps with absolute `sources`/`sourceRoot`, secrets/paths inside `sourcesContent`, or embedded `sourcesContent` | `"sourceRoot": "/home/alex/src"` |
| `PS005` | `error` | Risky files in the tarball: `.env*`, `.npmrc`, `*.pem`, `*.key`, `id_rsa*`, `*.p12`, `.git*`, `*.sqlite`, `*.log`, `coverage/`, `.DS_Store`, `.vscode/`, `.idea/` | `.env.production` |
| `PS006` | `warn`/`info` | Private IPs (`10.x`, `192.168.x`, `172.16-31.x`), `*.internal`/`*.corp`/`*.local`, `localhost` in non-test code, custom `publishConfig.registry`, non-npmjs lockfile `resolved` hosts | `http://192.168.1.50:8080` |
| `PS007` | `info`/`warn` | Total unpacked size, file count, top 5 largest files; warns over thresholds | `totalSize > 10 MB` |
| `PS008` | `info` | Email addresses in shipped files (excluding `package.json` `author`/`contributors`/`bugs` and example domains) | `dev@privatecorp.com` |

See [docs/RULES.md](docs/RULES.md) for full details on each rule.

## Configuration (`.packsaferc.json`)

Optional `.packsaferc.json` in the package root:

```json
{
  "failOn": "error",
  "allowPackageJsonIdentity": true,
  "denyWords": ["ProjectApollo"],
  "thresholds": {
    "maxTotalBytes": 10485760,
    "maxFileCount": 500,
    "maxFileBytes": 2097152
  },
  "allow": [
    {
      "rule": "PS006",
      "pattern": "localhost:3000",
      "reason": "Documented local dev server URL in README.md"
    }
  ]
}
```

Every `allow` entry requires a non-empty `reason` string. You can also suppress a single line in text files using a comment:

```js
// packsafe-ignore-next-line PS001
const example = "/home/alexsmith/demo";
```

## CI recipe (GitHub Actions)

```yaml
- name: Audit npm publish tarball
  run: npx packsafe --format github
```

Or upload SARIF to GitHub Code Scanning:

```yaml
- name: Run packsafe
  run: npx packsafe --format sarif > packsafe.sarif
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: packsafe.sarif
```

## FAQ

**How is `packsafe` different from `gitleaks` or `secretlint`?**
`gitleaks` and `secretlint` scan your git repository or working tree for credentials. They miss `.gitignore`d build artifacts (`dist/`, `*.map`) that `npm publish` ships, and they do not know your local OS username, hostname, or git `user.name`/`user.email`. `packsafe` scans the exact npm publish set offline with zero runtime dependencies.

## Comparison

| Feature | `packsafe` | `publint` | `npm-packlist` | `secretlint` | `gitleaks` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Audits exact npm publish set (`dist/`, `.map`, etc.) | Yes | Yes | Lists only | Repo files | Git repo/history |
| Auto-detects OS username, hostname, git identity | Yes | No | No | No | No |
| Detects local absolute home paths (`PS001`) | Yes | No | No | No | No |
| Parses `.map` sourcemaps & `sourcesContent` | Yes | No | No | No | No |
| Secret & token detection with redaction | Yes | No | No | Yes | Yes |
| Zero runtime dependencies & fully offline | Yes | No | No | No | Go binary |

See [docs/COMPETITORS.md](docs/COMPETITORS.md) for the full evaluation.

## Limitations

No static tool can guarantee that nothing leaks. In particular, minified or obfuscated bundles, binary files, encrypted or base64-encoded secrets, and files larger than 5 MB are not deeply inspected. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## License

[MIT](LICENSE)

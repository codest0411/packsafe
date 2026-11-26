# PackSafe Rules Reference

## PS001 — Absolute Home Paths (`error`)
Detects absolute local home directory paths in shipped text files and sourcemaps:
- POSIX: `/home/<name>`, `/Users/<name>`
- Windows: `C:\Users\<name>`, `C:/Users/<name>`, and JSON-escaped `C:\\Users\\<name>`
- File URLs: `file:///home/<name>`, `file:///Users/<name>`, `file:///C:/Users/<name>`

Generic documentation placeholders (`yourname`, `username`, `user`, `runner`, `example`, `alice`, `bob`, `admin`, `root`, `vscode`, etc.) are excluded.

## PS002 — Machine Identity (`error`)
Auto-detects the current machine's identity (injectable in tests):
- `os.userInfo().username`
- `os.homedir()` and its basename
- `os.hostname()` and its short hostname
- `git config user.name` and `git config user.email`

Matches are case-insensitive and boundary-aware. Values shorter than 4 characters, common generic words (`root`, `admin`, `user`, `ubuntu`, `runner`, etc.), and values intentionally published in `package.json` (`author`, `contributors`, `maintainers`, `repository`, `bugs`, `homepage`) are excluded by default (`allowPackageJsonIdentity: true`). Also checks `denyWords` from `.packsaferc.json`.

## PS003 — Secrets and Tokens (`error`)
Detects high-signal credential patterns using linear-time regular expressions:
- Private key headers (`-----BEGIN ... PRIVATE KEY-----`)
- npm tokens (`npm_` + 36 alphanumeric characters)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
- AWS Access Key IDs (`AKIA...`, `ASIA...`)
- Slack tokens (`xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-`)
- `.npmrc` `_authToken=` lines
- Generic `password|passwd|secret|api_key|access_token|auth_token|private_key = "<value>"` assignments (12+ chars, excluding obvious placeholders)

All matched values are redacted in output (`first4...[redacted len=N]`).

## PS004 — Sourcemap Leaks (`error` / `warn` / `info`)
Parses `*.map` JSON files:
- `warn` if the `.map` file is malformed JSON
- `error` if `sourceRoot` or any `sources[]` entry contains an absolute local path
- Scans decoded `sourcesContent[]` entries with text rules (`PS001`, `PS002`, `PS003`, `PS006`, `PS008`)
- `info` when `sourcesContent` is embedded in the shipped sourcemap

## PS005 — Risky Files (`error`)
Flags sensitive or unintended files in the publish set (runs on both text and binary files):
`.env`, `.env.*`, `.npmrc`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_dsa*`, `id_ecdsa*`, `id_ed25519*`, `.git/*`, `.gitconfig`, `.git-credentials`, `.gitmodules`, `*.sqlite`, `*.sqlite3`, `*.db`, `*.log`, `coverage/*`, `.nyc_output/*`, `.DS_Store`, `Thumbs.db`, `.vscode/*`, `.idea/*`.

## PS006 — Internal URLs & Registries (`warn` / `info`)
- `warn`: Private IPv4 addresses (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`)
- `warn`: Internal hostnames (`*.internal`, `*.corp`, `*.local`, `*.lan`, `*.intranet`)
- `info`: `http://localhost` / `http://127.0.0.1` URLs in non-test shipped files
- `warn`: Non-default `package.json` `publishConfig.registry`
- `warn`: Non-npmjs `resolved` hosts in shipped lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`)

## PS007 — Size Sanity (`info` / `warn`)
Reports total unpacked size, file count, and the top 5 largest files (`info`), and warns (`warn`) when configurable thresholds are exceeded:
- `maxTotalBytes` (default 10 MB)
- `maxFileCount` (default 500)
- `maxFileBytes` (default 2 MB)

## PS008 — Email Addresses (`info`)
Flags email addresses in shipped text files unless they match `package.json` public metadata (`author`, `contributors`, `bugs`) or common placeholder domains (`example.com`, `example.org`, `example.net`, `users.noreply.github.com`, `localhost`, `test.com`).

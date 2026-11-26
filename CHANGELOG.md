# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-11-26

### Added
- Initial release of `packsafe` CLI and programmatic API.
- Exact npm publish-set resolution via `npm pack --dry-run --json --ignore-scripts` with Windows `npm_execpath` / `npm-cli.js` resolution (`shell: false`).
- Injectable machine identity detection (OS username, homedir, hostname, git `user.name` / `user.email`) with `package.json` public metadata allowlisting.
- Rules `PS001`–`PS008` covering home paths, machine identity, secrets/tokens (with redaction), `.map` sourcemaps, risky files, internal URLs/registries, size sanity, and email addresses.
- `.packsaferc.json` strict schema validation and `packsafe-ignore-next-line` inline suppression.
- Reporters for `human`, `json`, `github`, and `sarif`.

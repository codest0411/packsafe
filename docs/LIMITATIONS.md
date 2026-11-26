# Known Limitations

`packsafe` is a defense-in-depth pre-publish gate, not a guarantee that an npm package is completely free of sensitive data.

1. **Minified and obfuscated code**: Heavy minification or string concatenation (e.g., `"npm_" + tokenPart`) can split patterns or remove word boundaries so regexes do not match.
2. **Encoded or encrypted secrets**: Base64-encoded, hex-encoded, or encrypted payloads are not decoded before scanning.
3. **Binary files**: Files containing NUL bytes (`0x00`) are skipped by content rules (`PS001`–`PS004`, `PS006`, `PS008`), though their filenames are still checked by `PS005` and their sizes by `PS007`.
4. **5 MB per-file scan limit**: Individual files larger than 5 MB are skipped for content scanning with a `PS007` warning to keep memory usage and execution time bounded.
5. **Requires `npm` CLI**: `packsafe` relies on `npm pack --dry-run --json --ignore-scripts` to determine the exact publish set. If `npm` is unavailable, `packsafe` exits with code `2` rather than guessing the file list.
6. **Generic secrets**: `PS003` uses high-precision patterns to avoid drowning maintainers in false positives; arbitrary high-entropy strings without a recognizable prefix or assignment key are not flagged.
7. **Publish-time scripts**: By default, `packsafe` passes `--ignore-scripts`. If a package uses `prepack` to generate `dist/` files, run the build step before running `packsafe` (or opt into `--run-scripts` only on trusted packages).

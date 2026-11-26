/**
 * Safely parse a Source Map v3 JSON file.
 * Never throws on malformed or unexpected JSON shapes.
 *
 * @param {string} rawText
 * @returns {{
 *   ok: true,
 *   sourceRoot: string,
 *   sources: string[],
 *   sourcesContent: Array<string | null>
 * } | { ok: false, error: string }}
 */
export function parseSourceMap(rawText) {
  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, error: `Malformed sourcemap JSON: ${msg}` };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: 'Sourcemap root must be a JSON object' };
  }

  const obj = /** @type {Record<string, unknown>} */ (parsed);
  const sourceRoot = typeof obj.sourceRoot === 'string' ? obj.sourceRoot : '';
  const sources = Array.isArray(obj.sources)
    ? obj.sources.map((s) => (typeof s === 'string' ? s : ''))
    : [];
  const sourcesContent = Array.isArray(obj.sourcesContent)
    ? obj.sourcesContent.map((c) => (typeof c === 'string' ? c : null))
    : [];

  return {
    ok: true,
    sourceRoot,
    sources,
    sourcesContent
  };
}

import { parseSourceMap } from '../sourcemap.js';

/** @type {import('./types.js').RuleMeta} */
export const RULE_PS004 = {
  id: 'PS004',
  name: 'sourcemap-leaks',
  defaultSeverity: 'error',
  description: 'Parses *.map sourcemaps for absolute local paths in sources/sourceRoot and scans embedded sourcesContent.'
};

const ABS_PATH_IN_SOURCEMAP_RE = /^(?:file:\/\/|\/(?:home|Users|var|opt|srv|etc|tmp|mnt|Volumes)\/|[A-Za-z]:(?:\\|\/))/;

/**
 * Scan a `.map` sourcemap file.
 *
 * @param {string} relPosix
 * @param {string} normalizedText
 * @param {(line: string, virtualFile: string, lineNum: number) => import('./types.js').Finding[]} scanTextLine
 * @returns {import('./types.js').Finding[]}
 */
export function scanSourceMapPS004(relPosix, normalizedText, scanTextLine) {
  /** @type {import('./types.js').Finding[]} */
  const findings = [];
  const parsed = parseSourceMap(normalizedText);

  if (!parsed.ok) {
    findings.push({
      ruleId: RULE_PS004.id,
      severity: 'warn',
      file: relPosix,
      message: parsed.error
    });
    return findings;
  }

  if (parsed.sourceRoot && ABS_PATH_IN_SOURCEMAP_RE.test(parsed.sourceRoot)) {
    findings.push({
      ruleId: RULE_PS004.id,
      severity: 'error',
      file: relPosix,
      message: `Sourcemap sourceRoot contains an absolute local path (${parsed.sourceRoot})`
    });
  }

  for (let i = 0; i < parsed.sources.length; i += 1) {
    const src = parsed.sources[i] ?? '';
    if (src && ABS_PATH_IN_SOURCEMAP_RE.test(src)) {
      findings.push({
        ruleId: RULE_PS004.id,
        severity: 'error',
        file: relPosix,
        message: `Sourcemap sources[${i}] contains an absolute local path (${src})`
      });
    }
  }

  let hasEmbeddedContent = false;
  for (let i = 0; i < parsed.sourcesContent.length; i += 1) {
    const content = parsed.sourcesContent[i];
    if (typeof content !== 'string' || content.length === 0) continue;
    hasEmbeddedContent = true;

    const sourceLabel = parsed.sources[i] || `sourcesContent[${i}]`;
    const virtualFile = `${relPosix} (${sourceLabel})`;
    const lines = content.replace(/\r\n?/g, '\n').split('\n');
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx += 1) {
      const line = lines[lineIdx] ?? '';
      const subFindings = scanTextLine(line, virtualFile, lineIdx + 1);
      for (const f of subFindings) {
        findings.push(f);
      }
    }
  }

  if (hasEmbeddedContent) {
    findings.push({
      ruleId: RULE_PS004.id,
      severity: 'info',
      file: relPosix,
      message: 'Sourcemap ships embedded sourcesContent (original source code is included in the tarball)'
    });
  }

  return findings;
}

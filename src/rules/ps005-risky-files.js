/** @type {import('./types.js').RuleMeta} */
export const RULE_PS005 = {
  id: 'PS005',
  name: 'risky-files',
  defaultSeverity: 'error',
  description: 'Detects sensitive or unintended files (.env*, .npmrc, keys, .git*, databases, logs, coverage, editor/OS metadata).'
};

/** @type {Array<{ test: (relPosix: string, base: string) => boolean, label: string }>} */
const RISKY_FILE_MATCHERS = [
  {
    test: (_rel, base) => base === '.env' || base.startsWith('.env.'),
    label: 'Environment file (.env*)'
  },
  {
    test: (_rel, base) => base === '.npmrc',
    label: 'npm configuration file (.npmrc)'
  },
  {
    test: (_rel, base) => /\.(?:pem|key|p12|pfx)$/i.test(base),
    label: 'Cryptographic key or certificate file'
  },
  {
    test: (_rel, base) => /^(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?$/i.test(base),
    label: 'SSH key file'
  },
  {
    test: (rel, base) =>
      rel === '.git' ||
      rel.startsWith('.git/') ||
      rel.includes('/.git/') ||
      /^\.git(?:config|-credentials|modules)$/i.test(base),
    label: 'Git metadata or credential file (.git*)'
  },
  {
    test: (_rel, base) => /\.(?:sqlite|sqlite3|db)$/i.test(base),
    label: 'SQLite/database file'
  },
  {
    test: (_rel, base) => /\.log$/i.test(base),
    label: 'Log file (*.log)'
  },
  {
    test: (rel) =>
      rel === 'coverage' ||
      rel.startsWith('coverage/') ||
      rel.includes('/coverage/') ||
      rel === '.nyc_output' ||
      rel.startsWith('.nyc_output/'),
    label: 'Test coverage output directory'
  },
  {
    test: (_rel, base) => base === '.DS_Store' || base === 'Thumbs.db',
    label: 'OS metadata file (.DS_Store / Thumbs.db)'
  },
  {
    test: (rel) =>
      rel.startsWith('.vscode/') ||
      rel.includes('/.vscode/') ||
      rel.startsWith('.idea/') ||
      rel.includes('/.idea/'),
    label: 'Editor configuration folder (.vscode / .idea)'
  }
];

/**
 * Check whether a file path in the publish set is a risky file (PS005).
 * Runs on both text and binary files.
 *
 * @param {string} relPosix
 * @returns {import('./types.js').Finding[]}
 */
export function scanFilePathPS005(relPosix) {
  const parts = relPosix.split('/');
  const base = parts[parts.length - 1] ?? '';

  for (const matcher of RISKY_FILE_MATCHERS) {
    if (matcher.test(relPosix, base)) {
      return [
        {
          ruleId: RULE_PS005.id,
          severity: RULE_PS005.defaultSeverity,
          file: relPosix,
          message: `Risky file in publish set: ${matcher.label} (${relPosix})`
        }
      ];
    }
  }

  return [];
}

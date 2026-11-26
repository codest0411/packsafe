import { ALL_RULES } from '../rules/index.js';

/**
 * Format scan results as SARIF v2.1.0 JSON.
 *
 * @param {import('../rules/types.js').ScanResult} result
 * @param {string} [toolVersion]
 * @returns {string}
 */
export function formatSarif(result, toolVersion = '0.1.0') {
  const sarifLevel = (/** @type {'error' | 'warn' | 'info'} */ sev) =>
    sev === 'error' ? 'error' : sev === 'warn' ? 'warning' : 'note';

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'packsafe',
            version: toolVersion,
            informationUri: 'https://github.com/packsafe/packsafe',
            rules: ALL_RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.description },
              defaultConfiguration: {
                level: sarifLevel(r.defaultSeverity)
              }
            }))
          }
        },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel(f.severity),
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.file
                },
                ...(f.line
                  ? {
                      region: {
                        startLine: f.line,
                        ...(f.column ? { startColumn: f.column } : {})
                      }
                    }
                  : {})
              }
            }
          ]
        }))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2) + '\n';
}

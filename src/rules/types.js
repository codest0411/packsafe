/**
 * Shared JSDoc type definitions for packsafe rules and findings.
 *
 * @typedef {'error' | 'warn' | 'info'} Severity
 * @typedef {'error' | 'warn' | 'info' | 'none'} FailOnLevel
 *
 * @typedef {{
 *   ruleId: string,
 *   severity: Severity,
 *   file: string,
 *   line?: number,
 *   column?: number,
 *   message: string,
 *   snippet?: string
 * }} Finding
 *
 * @typedef {{
 *   id: string,
 *   name: string,
 *   defaultSeverity: Severity,
 *   description: string
 * }} RuleMeta
 *
 * @typedef {{
 *   packageName: string,
 *   packageVersion: string,
 *   fileCount: number,
 *   totalSize: number,
 *   topLargest: Array<{ file: string, size: number }>,
 *   findings: Finding[],
 *   counts: { error: number, warn: number, info: number },
 *   failOn: FailOnLevel,
 *   failed: boolean
 * }} ScanResult
 */

export {};

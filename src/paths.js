import fs from 'node:fs';
import path from 'node:path';

/**
 * Normalize any OS path separators to POSIX forward slashes.
 * @param {string} filePath
 * @returns {string}
 */
export function toPosixPath(filePath) {
  return filePath.replace(/\\/g, '/');
}

/**
 * Strip a leading UTF-8 BOM and normalize CRLF/CR line endings to LF.
 * @param {string} text
 * @returns {string}
 */
export function normalizeText(text) {
  const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  return withoutBom.replace(/\r\n?/g, '\n');
}

/**
 * Detect whether a buffer likely represents binary data by checking for NUL bytes.
 * @param {Buffer} buf
 * @returns {boolean}
 */
export function isBinaryBuffer(buf) {
  const limit = Math.min(buf.length, 8192);
  for (let i = 0; i < limit; i += 1) {
    if (buf[i] === 0) {
      return true;
    }
  }
  return false;
}

/**
 * Resolve a relative file path from the npm publish list safely inside the package root.
 * Rejects absolute paths, NUL bytes, `..` traversal, and symlinks that escape the root.
 *
 * @param {string} rootRealPath - Realpath-resolved package root directory.
 * @param {string} relPath - Relative path reported by npm.
 * @returns {{ ok: true, absPath: string, relPosix: string } | { ok: false, reason: string }}
 */
export function resolveSafePackagePath(rootRealPath, relPath) {
  if (typeof relPath !== 'string' || relPath.length === 0) {
    return { ok: false, reason: 'Empty file path in publish list' };
  }
  if (relPath.includes('\0')) {
    return { ok: false, reason: 'NUL byte in file path' };
  }

  const posix = toPosixPath(relPath);
  if (posix.startsWith('/') || /^[A-Za-z]:\//.test(posix) || posix.startsWith('//')) {
    return { ok: false, reason: `Absolute path rejected: ${posix}` };
  }

  const segments = posix.split('/');
  if (segments.some((seg) => seg === '..')) {
    return { ok: false, reason: `Path traversal rejected: ${posix}` };
  }

  const candidate = path.resolve(rootRealPath, ...segments);
  const rootPrefix = rootRealPath.endsWith(path.sep) ? rootRealPath : rootRealPath + path.sep;
  if (candidate !== rootRealPath && !candidate.startsWith(rootPrefix)) {
    return { ok: false, reason: `Path escapes package root: ${posix}` };
  }

  let realTarget;
  try {
    realTarget = fs.realpathSync(candidate);
  } catch {
    return { ok: false, reason: `File does not exist or is unreadable: ${posix}` };
  }

  if (realTarget !== rootRealPath && !realTarget.startsWith(rootPrefix)) {
    return { ok: false, reason: `Symlink escapes package root: ${posix}` };
  }

  return {
    ok: true,
    absPath: realTarget,
    relPosix: toPosixPath(path.relative(rootRealPath, candidate))
  };
}

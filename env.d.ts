// Minimal ambient declarations for Node.js built-ins so `tsc --checkJs` runs
// with zero extra devDependencies beyond `typescript` and `eslint`.

declare namespace NodeJS {
  interface ProcessEnv {
    [key: string]: string | undefined;
  }
  type Platform =
    | 'aix'
    | 'android'
    | 'darwin'
    | 'freebsd'
    | 'haiku'
    | 'linux'
    | 'openbsd'
    | 'sunos'
    | 'win32'
    | 'cygwin'
    | 'netbsd';
  interface WriteStream {
    isTTY?: boolean;
    write(str: string): boolean;
  }
  interface Process {
    argv: string[];
    env: ProcessEnv;
    execPath: string;
    platform: Platform;
    exitCode?: number;
    stdout: WriteStream;
    stderr: WriteStream;
    cwd(): string;
  }
}

interface ImportMeta {
  url: string;
  dirname: string;
  filename: string;
}

declare const process: NodeJS.Process;

interface BufferConstructor {
  from(value: string, encoding?: string): Buffer;
  from(array: number[]): Buffer;
}

interface Buffer extends Uint8Array {
  toString(encoding?: string): string;
}

declare const Buffer: BufferConstructor;

declare module 'node:fs' {
  export function existsSync(path: string): boolean;
  export function readFileSync(path: string, encoding: 'utf8'): string;
  export function readFileSync(path: string): Buffer;
  export function writeFileSync(path: string, data: string | Buffer, encoding?: string): void;
  export function mkdirSync(path: string, options?: { recursive?: boolean }): void;
  export function mkdtempSync(prefix: string): string;
  export function rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
  export function realpathSync(path: string): string;
  export function statSync(path: string): { size: number };
  export function symlinkSync(target: string, path: string): void;
}

declare module 'node:path' {
  export const sep: string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
  export function dirname(p: string): string;
  export function basename(p: string): string;
  export function relative(from: string, to: string): string;
}

declare module 'node:os' {
  export function tmpdir(): string;
  export function homedir(): string;
  export function hostname(): string;
  export function userInfo(): { username: string };
}

declare module 'node:child_process' {
  export function execFile(
    file: string,
    args: string[],
    options: Record<string, unknown>,
    callback?: (err: Error | null, stdout: string, stderr: string) => void
  ): void;
}

declare module 'node:util' {
  export function promisify<T extends (...args: any[]) => any>(fn: T): (...args: any[]) => Promise<any>;
  export function parseArgs(config: Record<string, unknown>): {
    values: Record<string, any>;
    positionals: string[];
  };
}

declare module 'node:module' {
  export function createRequire(url: string): (id: string) => any;
}

declare module 'node:test' {
  export function describe(name: string, fn: () => void | Promise<void>): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
}

declare module 'node:assert/strict' {
  const assert: {
    equal(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    ok(value: unknown, message?: string): void;
    match(value: string, regexp: RegExp, message?: string): void;
    throws(fn: () => unknown, error?: unknown): void;
    doesNotThrow(fn: () => unknown): void;
    rejects(fn: () => Promise<unknown>, error?: unknown): Promise<void>;
  };
  export default assert;
}

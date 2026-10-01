import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

export type TempDir = {
  readonly path: string;
  child(...segments: string[]): string;
  cleanup(): void;
};

/** Creates an isolated temporary directory for a test case. */
export function createTempDir(prefix = 'nvd-mcp-test-'): TempDir {
  const directory = mkdtempSync(path.join(tmpdir(), prefix));
  let cleaned = false;
  return {
    path: directory,
    child: (...segments: string[]) => path.join(directory, ...segments),
    cleanup: () => {
      if (cleaned) {
        return;
      }
      cleaned = true;
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

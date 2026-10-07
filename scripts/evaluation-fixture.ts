import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { seedEvaluationFixture } from '../evaluations/fixture.js';
import { NvdMockServer } from '../tests/helpers/nvd-mock-server.js';
import { createTempDir } from '../tests/helpers/temp.js';

// Development-only stdio wrapper: the real server talks solely to a loopback fixture API.
const mock = await NvdMockServer.start();
seedEvaluationFixture(mock);
const temp = createTempDir();
const child = spawn(process.execPath, [fileURLToPath(new URL('../dist/main.js', import.meta.url))], {
  stdio: 'inherit',
  env: {
    ...process.env,
    NVD_API_KEY: '', NVD_BASE_URL: mock.baseUrl,
    NVD_MIN_INTERVAL_MS: '0', NVD_MAX_RETRIES: '0',
    SQLITE_PATH: temp.child('nvd.sqlite'), CACHE_DIRECTORY: temp.child('cache'),
    CACHE_CLEANUP_INTERVAL_SECONDS: '0',
  },
});
let stopping = false;
function stop(signal: NodeJS.Signals) {
  if (stopping) return;
  stopping = true;
  child.kill(signal);
}
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
child.once('error', async () => {
  await mock.stop();
  temp.cleanup();
  process.exitCode = 1;
});
child.once('exit', async code => {
  await mock.stop();
  temp.cleanup();
  process.exitCode = code ?? 1;
});

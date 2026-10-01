import type { AppConfig } from '../config/env.js';
import type { Clock } from '../domain/ports.js';
import type { Logger } from '../shared/logger.js';
import type { CveService } from '../application/cve-service.js';
import type { CveHistoryService } from '../application/cve-history-service.js';
import type { CpeService } from '../application/cpe-service.js';
import type { CpeMatchService } from '../application/cpe-match-service.js';

/** Everything a tool handler may use. The MCP layer never touches NVD or SQLite directly. */
export type ToolContext = {
  config: AppConfig;
  logger: Logger;
  clock: Clock;
  services: {
    cve: CveService;
    cveHistory: CveHistoryService;
    cpe: CpeService;
    cpeMatch: CpeMatchService;
  };
};

import type { AnyToolDefinition } from '../tool.js';

import { getCveTool } from './get-cve.tool.js';
import { getCveSummaryTool } from './get-cve-summary.tool.js';
import { getCvesTool } from './get-cves.tool.js';
import { searchCvesTool } from './search-cves.tool.js';
import { getCveHistoryTool } from './get-cve-history.tool.js';
import { getRecentCvesTool } from './get-recent-cves.tool.js';
import { getModifiedCvesTool } from './get-modified-cves.tool.js';
import { searchCpesTool } from './search-cpes.tool.js';
import { getCpeTool } from './get-cpe.tool.js';
import { searchCpeMatchesTool } from './search-cpe-matches.tool.js';

/**
 * The complete public tool surface.
 *
 * Order matters only for `tools/list`. Tool names are `snake_case` and carry an `nvd_` prefix so
 * they stay unambiguous when this server runs next to other MCP servers.
 */
export const allTools: readonly AnyToolDefinition[] = [
  getCveTool,
  getCveSummaryTool,
  getCvesTool,
  searchCvesTool,
  getCveHistoryTool,
  getRecentCvesTool,
  getModifiedCvesTool,
  searchCpesTool,
  getCpeTool,
  searchCpeMatchesTool,
];

export const TOOL_COUNT = allTools.length;

export const TOOL_NAMES: readonly string[] = allTools.map((tool) => tool.name);

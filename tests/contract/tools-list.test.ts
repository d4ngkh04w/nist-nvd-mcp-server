import { afterEach, describe, expect, it } from 'vitest';

import { createHarness, type Harness } from '../helpers/harness.js';

const EXPECTED_TOOL_NAMES = [
  'get_cve',
  'get_cve_summary',
  'get_cves',
  'search_cves',
  'get_cve_history',
  'get_recent_cves',
  'get_modified_cves',
  'search_cpes',
  'get_cpe',
  'search_cpe_matches',
];

type ToolDescriptor = {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
};

describe('MCP contract: tools/list', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('advertises exactly the ten documented tools', async () => {
    harness = await createHarness();
    const response = await harness.client?.listTools();
    const tools = (response?.tools ?? []) as ToolDescriptor[];

    expect(tools.map((tool) => tool.name)).toEqual(EXPECTED_TOOL_NAMES);
    for (const tool of tools) {
      expect(tool.name.startsWith('nvd_')).toBe(false);
      expect(tool.title ?? '').not.toHaveLength(0);
      expect(tool.description ?? '').not.toHaveLength(0);
    }
  });

  it('publishes an input and an output schema for every tool without leaking cachePolicy or startIndex', async () => {
    harness = await createHarness();
    const response = await harness.client?.listTools();
    const tools = (response?.tools ?? []) as ToolDescriptor[];

    for (const tool of tools) {
      expect(tool.inputSchema, `${tool.name} input schema`).toBeDefined();
      expect(tool.outputSchema, `${tool.name} output schema`).toBeDefined();
      expect(tool.inputSchema?.['type']).toBe('object');

      const serializedInput = JSON.stringify(tool.inputSchema);
      expect(serializedInput).not.toContain('cachePolicy');
      expect(serializedInput).not.toContain('"startIndex"');
      expect(serializedInput).not.toContain('apiKey');

      const outputProperties = (tool.outputSchema?.['properties'] ?? {}) as Record<string, unknown>;
      expect(Object.keys(outputProperties).length, `${tool.name} output properties`).toBeGreaterThan(0);
    }
  });

  it('declares the pagination and cache metadata blocks required by the contract', async () => {
    harness = await createHarness();
    const response = await harness.client?.listTools();
    const tools = (response?.tools ?? []) as ToolDescriptor[];

    const collectionTools = tools.filter((tool) =>
      ['search_cves', 'get_cve_history', 'get_recent_cves', 'get_modified_cves', 'search_cpes', 'search_cpe_matches'].includes(
        tool.name,
      ),
    );
    expect(collectionTools).toHaveLength(6);

    for (const tool of collectionTools) {
      const properties = (tool.outputSchema?.['properties'] ?? {}) as Record<string, unknown>;
      expect(properties['items'], `${tool.name}.items`).toBeDefined();
      const pagination = properties['pagination'] as { properties?: Record<string, unknown> } | undefined;
      expect(pagination?.properties, `${tool.name}.pagination`).toBeDefined();
      expect(Object.keys(pagination?.properties ?? {}).sort()).toEqual(
        ['hasMore', 'nextCursor', 'pageSize', 'returned', 'totalResults'].sort(),
      );
      expect(Object.keys(pagination?.properties ?? {})).not.toContain('startIndex');
    }

    for (const tool of tools) {
      const properties = (tool.outputSchema?.['properties'] ?? {}) as Record<string, unknown>;
      const meta = properties['meta'] as { properties?: Record<string, unknown> } | undefined;
      expect(meta?.properties?.['cacheStatus'], `${tool.name}.meta.cacheStatus`).toBeDefined();
      expect(meta?.properties?.['warnings'], `${tool.name}.meta.warnings`).toBeDefined();
      expect(meta?.properties?.['stale'], `${tool.name}.meta.stale`).toBeDefined();
    }
  });

  it('marks every tool as read-only and does not advertise sync or health tools', async () => {
    harness = await createHarness();
    const response = await harness.client?.listTools();
    const tools = (response?.tools ?? []) as ToolDescriptor[];

    for (const tool of tools) {
      expect(tool.annotations?.['readOnlyHint'], `${tool.name} readOnlyHint`).toBe(true);
    }
    const names = tools.map((tool) => tool.name);
    expect(names.filter((name) => /sync|health|cleanup/i.test(name))).toEqual([]);
  });

  it('never documents a forwarded filter as locally applied or points at a non-existent cursor path', async () => {
    harness = await createHarness();
    const response = await harness.client?.listTools();
    const tools = (response?.tools ?? []) as ToolDescriptor[];

    // `vulnStatuses`, `isVulnerable` and `kevStartDate`/`kevEndDate` are forwarded to NVD,
    // so the model must not be told they run locally. `meta.pagination` does not exist:
    // the cursor lives at the top-level `pagination.nextCursor`.
    const staleClaims = [
      /NVD (?:API )?rejects this parameter/,
      /no KEV date filter/,
      /applied (?:client-side|locally) and reported through meta\.filtersAppliedClientSide/,
      /meta\.pagination/,
    ];

    for (const tool of tools) {
      const documentation = [tool.description ?? '', JSON.stringify(tool.inputSchema), JSON.stringify(tool.outputSchema)].join('\n');
      for (const claim of staleClaims) {
        expect(documentation, `${tool.name} documentation`).not.toMatch(claim);
      }
    }
  });

  it('documents the cursor at the top-level pagination.nextCursor field', async () => {
    harness = await createHarness();
    const response = await harness.client?.listTools();
    const tools = (response?.tools ?? []) as ToolDescriptor[];
    const cursorTools = tools.filter((tool) => JSON.stringify(tool.inputSchema).includes('"cursor"'));

    expect(cursorTools.length).toBeGreaterThan(0);
    for (const tool of cursorTools) {
      const serializedInput = JSON.stringify(tool.inputSchema);
      expect(serializedInput, `${tool.name} cursor description`).toContain('pagination.nextCursor');
    }
  });

  it('reports the server identity', async () => {
    harness = await createHarness();
    const version = harness.client?.getServerVersion();
    expect(version?.name).toBe('nvd-nist-mcp');
    expect(version?.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

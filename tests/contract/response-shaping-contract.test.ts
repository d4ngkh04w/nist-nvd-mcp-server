import { afterEach, describe, expect, it } from 'vitest';

import {
  CPE_MATCH_FIELDS,
  CPE_RECORD_FIELDS,
  CVE_CHANGE_EVENT_FIELDS,
  CVE_DETAILS_FIELDS,
  CVE_SUMMARY_FIELDS,
} from '../../src/domain/field-projection.js';
import { CPE_23_MAX_COMPONENTS } from '../../src/domain/validation.js';
import { RESPONSE_ORDERINGS } from '../../src/application/response-meta.js';
import { createHarness, type Harness } from '../helpers/harness.js';

/** Tools whose payload can be narrowed with `fields`. */
const PROJECTABLE_TOOLS: Array<{ name: string; fields: readonly string[] }> = [
  { name: 'nvd_get_cve', fields: CVE_DETAILS_FIELDS },
  { name: 'nvd_get_cve_summary', fields: CVE_SUMMARY_FIELDS },
  { name: 'nvd_get_cves', fields: CVE_SUMMARY_FIELDS },
  { name: 'nvd_search_cves', fields: CVE_SUMMARY_FIELDS },
  { name: 'nvd_get_recent_cves', fields: CVE_SUMMARY_FIELDS },
  { name: 'nvd_get_modified_cves', fields: CVE_SUMMARY_FIELDS },
  { name: 'nvd_get_cve_history', fields: CVE_CHANGE_EVENT_FIELDS },
  { name: 'nvd_search_cpe_matches', fields: CPE_MATCH_FIELDS },
  { name: 'nvd_search_cpes', fields: CPE_RECORD_FIELDS },
];

type ToolDescriptor = {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
};

function properties(schema: Record<string, unknown> | undefined): Record<string, unknown> {
  return (schema?.['properties'] ?? {}) as Record<string, unknown>;
}

function descriptionOf(schema: Record<string, unknown> | undefined, key: string): string {
  const property = properties(schema)[key] as { description?: string } | undefined;
  return property?.description ?? '';
}

describe('MCP contract: response shaping and metadata documentation', () => {
  let harness: Harness | undefined;

  afterEach(async () => {
    await harness?.close();
    harness = undefined;
  });

  it('publishes a `fields` parameter with its allowlist on exactly the payload-heavy tools', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];

    for (const { name, fields } of PROJECTABLE_TOOLS) {
      const tool = tools.find((entry) => entry.name === name);
      expect(tool, `${name} is advertised`).toBeDefined();
      const described = descriptionOf(tool?.inputSchema, 'fields');
      expect(described, `${name}.fields description`).toContain('Supported:');
      for (const field of fields) {
        expect(described, `${name}.fields lists ${field}`).toContain(field);
      }
      expect(described).toContain('meta.fieldsApplied');
    }

    // A single dictionary entry carries every key, so it carries no `fields` parameter.
    {
      const tool = tools.find((entry) => entry.name === 'nvd_get_cpe');
      expect(properties(tool?.inputSchema)['fields'], 'nvd_get_cpe has no fields').toBeUndefined();
    }
  });

  it('publishes `metaOnly` on exactly the paged tools and keeps the position opaque', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];

    // Every tool that returns a pagination block accepts the metadata-only mode.
    const paged = tools.filter((tool) => {
      const output = properties(tool.outputSchema)['pagination'] as
        | { properties?: Record<string, unknown> }
        | undefined;
      return output?.properties !== undefined;
    });
    expect(paged.map((tool) => tool.name).sort()).toEqual(
      [
        'nvd_get_cve_history',
        'nvd_get_modified_cves',
        'nvd_get_recent_cves',
        'nvd_search_cpe_matches',
        'nvd_search_cpes',
        'nvd_search_cves',
      ].sort(),
    );
    for (const tool of paged) {
      const described = descriptionOf(tool.inputSchema, 'metaOnly');
      expect(described, `${tool.name}.metaOnly description`).toContain('empty array');
      expect(described).toContain('pagination.returned');
      const pagination = properties(tool.outputSchema)['pagination'] as {
        properties?: Record<string, unknown>;
      };
      const keys = Object.keys(pagination.properties ?? {});
      expect(keys, `${tool.name}.pagination.page`).toContain('page');
      expect(keys).toContain('pageCount');
      // The upstream offset must stay opaque: only the ordinal is published.
      expect(keys).not.toContain('startIndex');
      expect(
        (pagination.properties?.['pageCount'] as { description?: string }).description,
      ).toContain('estimate');
    }

    // The batch tool has no pagination block but still lets the item array be suppressed.
    const batch = tools.find((entry) => entry.name === 'nvd_get_cves');
    expect(properties(batch?.inputSchema)['metaOnly'], 'nvd_get_cves.metaOnly').toBeDefined();
    expect(descriptionOf(batch?.inputSchema, 'metaOnly')).toContain('empty array');

    for (const name of ['nvd_get_cve', 'nvd_get_cve_summary', 'nvd_get_cpe']) {
      const tool = tools.find((entry) => entry.name === name);
      expect(properties(tool?.inputSchema)['metaOnly'], `${name} has no metaOnly`).toBeUndefined();
    }
  });

  it('declares meta.fieldsApplied and the ordering enum on every tool', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];

    for (const tool of tools) {
      const meta = properties(tool.outputSchema)['meta'] as
        | { properties?: Record<string, unknown> }
        | undefined;
      const metaProperties = meta?.properties ?? {};
      expect(metaProperties['fieldsApplied'], `${tool.name}.meta.fieldsApplied`).toBeDefined();
      const ordering = metaProperties['ordering'] as
        | { enum?: string[]; description?: string }
        | undefined;
      expect(ordering, `${tool.name}.meta.ordering`).toBeDefined();
      expect(ordering?.enum, `${tool.name}.meta.ordering enum`).toEqual([
        'published_desc',
        'last_modified_desc',
        'change_created_asc',
        'nvd_default',
      ]);
      // The published enum must not drift away from the values the services can produce.
      expect(ordering?.enum).toEqual([...RESPONSE_ORDERINGS]);
    }
  });

  it('documents the KEV single-day query and the date-only end expansion', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];
    const searchCves = tools.find((tool) => tool.name === 'nvd_search_cves');

    const documentation = JSON.stringify(searchCves?.inputSchema);
    expect(documentation).toContain('addedOn');
    expect(documentation).toContain('2021-11-03');
    expect(documentation).toContain('23:59:59.999');
    expect(documentation).toMatch(/mutually exclusive with addedBetween/);
  });

  it('distinguishes cpeMatchString, matchStringSearch and matchCriteriaId', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];

    const matches = tools.find((tool) => tool.name === 'nvd_search_cpe_matches');
    expect(matches?.description).toContain('cveId');
    expect(matches?.description).toContain('matchCriteriaId');
    expect(matches?.description).toContain('matchStringSearch');
    expect(matches?.description).toContain('cpeMatchString');
    expect(matches?.description).toContain('cpeNameId');
    // A criteria UUID is not a dictionary id, and the component limit is part of the contract.
    expect(matches?.description).toMatch(/matchCriteriaId: a criteria UUID[^.]*never a CPE dictionary id/);
    expect(matches?.description).toContain(String(CPE_23_MAX_COMPONENTS));
    expect(descriptionOf(matches?.inputSchema, 'matchStringSearch')).toContain(
      String(CPE_23_MAX_COMPONENTS),
    );

    const cpes = tools.find((tool) => tool.name === 'nvd_search_cpes');
    expect(cpes?.description).toContain('matchCriteriaId is a CPE Match Criteria UUID');
    expect(descriptionOf(cpes?.inputSchema, 'matchCriteriaId')).toContain('nvd_search_cpe_matches');
  });

  it('moves the includeDeprecated caveat and the totalResults semantics into the parameter docs', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];
    const cpes = tools.find((tool) => tool.name === 'nvd_search_cpes');

    const includeDeprecated = descriptionOf(cpes?.inputSchema, 'includeDeprecated');
    expect(includeDeprecated).toMatch(/NVD CPE API rejects/i);
    expect(includeDeprecated).toContain('meta.filteredOut');
    expect(includeDeprecated).toContain('totalResults');

    const totalResults = properties(
      (properties(cpes?.outputSchema)['pagination'] as Record<string, unknown> | undefined),
    )['totalResults'] as { description?: string } | undefined;
    expect(totalResults?.description).toMatch(/upstream/i);
    expect(totalResults?.description).toMatch(/before local filtering/i);
  });

  it('surfaces the affectedProducts truncation cap in the summary tool documentation', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];
    const summary = tools.find((tool) => tool.name === 'nvd_get_cve_summary');
    expect(summary?.description).toMatch(/affectedProducts is capped at \d+/);
    expect(summary?.description).toContain('fields:["id","published","primaryCvss","isKnownExploited","kevDateAdded"]');
  });

  it('keeps the default response contract intact: item keys stay optional but documented', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];
    const summary = tools.find((tool) => tool.name === 'nvd_get_cve_summary');
    const data = properties(summary?.outputSchema)['data'] as
      | { properties?: Record<string, unknown>; required?: string[] }
      | undefined;

    // `fields` can omit any key, so the published schema marks none of them as required; the
    // allowlist in the input description is the authoritative list of what an omitted list returns.
    expect(data?.required ?? []).toEqual([]);
    for (const field of CVE_SUMMARY_FIELDS) {
      expect(data?.properties?.[field], `data.${field}`).toBeDefined();
    }
  });

  it('documents the date-window, cursor and metric conventions a caller cannot infer', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];
    const find = (name: string) => tools.find((tool) => tool.name === name);

    // A date-only end covers the whole day, which is not obvious from a `YYYY-MM-DD` input.
    for (const name of ['nvd_search_cves', 'nvd_get_cve_history', 'nvd_search_cpe_matches']) {
      const end = descriptionOf(
        properties(find(name)?.inputSchema)[
          name === 'nvd_search_cves' ? 'published' : name === 'nvd_get_cve_history' ? 'changeBetween' : 'lastModified'
        ] as Record<string, unknown> | undefined,
        'end',
      );
      expect(end, `${name}.end`).toContain('23:59:59.999');
    }
    for (const name of ['nvd_get_recent_cves', 'nvd_get_modified_cves']) {
      expect(descriptionOf(find(name)?.inputSchema, 'end')).toContain('23:59:59.999');
    }

    // An opaque cursor is only usable when echoed unchanged, and a rejection says why.
    for (const name of ['nvd_search_cves', 'nvd_search_cpes', 'nvd_search_cpe_matches']) {
      const cursor = descriptionOf(find(name)?.inputSchema, 'cursor');
      expect(cursor, `${name}.cursor`).toContain('byte for byte');
      expect(cursor).toContain('details.reason');
    }

    // `primaryCvss` is NVD's preferred metric, which is not always CVSS 3.1.
    expect(JSON.stringify(find('nvd_get_cve_summary')?.outputSchema)).toMatch(
      /not always CVSS 3\.1/i,
    );
    expect(JSON.stringify(find('nvd_get_cves')?.outputSchema)).toMatch(
      /NVD's preferred metric/i,
    );

    // The default-on flags only matter when false, and the feed window default is exact.
    expect(find('nvd_get_cve')?.description).toMatch(
      /only matter when set to false[\s\S]*cannot prune inside the configurations tree/,
    );
    expect(descriptionOf(find('nvd_get_recent_cves')?.inputSchema, 'days')).toContain(
      'exactly 7',
    );
  });

  it('documents the lookup semantics that produce a wrong answer rather than an error', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];
    const find = (name: string) => tools.find((tool) => tool.name === name);

    // `matchStringSearch` returns one row per matching criteria, not per queried string, and a
    // version token it cannot parse degrades the query to the product prefix.
    const matches = find('nvd_search_cpe_matches');
    expect(matches?.description).toContain('not an exact lookup');
    expect(matches?.description).toContain('vendor and product prefix');
    expect(descriptionOf(matches?.inputSchema, 'matchStringSearch')).toContain(
      'compare the returned criteria field',
    );
    expect(descriptionOf(matches?.inputSchema, 'matchStringSearch')).toMatch(/loose/i);

    // A batch lookup returns whatever the identifiers resolve to, so identification needs the summary.
    const batch = find('nvd_get_cves');
    expect(batch?.description).toContain('never guesses which record a description');
    expect(batch?.description).toContain('keep summary in fields');
    expect(batch?.description).toContain('primaryCvss.version');

    // Both date windows are optional and independent, and `keyword` is tokenized.
    const search = find('nvd_search_cves');
    expect(search?.description).toContain('independent: supply either one or both');
    expect(search?.description).toMatch(/tokenization/);

    // A cursor freezes its window: omitting the window reuses it, a different one is rejected.
    for (const name of ['nvd_get_recent_cves', 'nvd_get_modified_cves']) {
      const description = find(name)?.description ?? '';
      expect(description, `${name} window reuse`).toContain('reuses the frozen window');
      expect(description, `${name} window conflict`).toContain('INVALID_CURSOR');
      expect(description, `${name} ordering fallback`).toContain('nvd_default');
    }

    // The two CPE dictionary UUIDs are syntactically identical, so the parameter itself warns.
    expect(descriptionOf(find('nvd_get_cpe')?.inputSchema, 'cpeNameId')).toContain(
      'Match Criteria UUID is not a dictionary id',
    );
  });

  it('documents what the response metadata echoes and what a filter that matched nothing means', async () => {
    harness = await createHarness();
    const tools = ((await harness.client?.listTools())?.tools ?? []) as ToolDescriptor[];
    const find = (name: string) => tools.find((tool) => tool.name === name);

    // `meta.window` is the window actually queried, which is the only way to confirm a relative
    // `days` resolved to the intended range.
    const metaSchema = JSON.stringify(find('nvd_get_recent_cves')?.outputSchema);
    expect(metaSchema).toMatch(/window actually queried/i);
    expect(metaSchema).toMatch(/two independent windows/i);

    // Reversing the window server side changes the item order but not the upstream total.
    for (const name of ['nvd_get_recent_cves', 'nvd_get_modified_cves', 'nvd_search_cves']) {
      expect(JSON.stringify(find(name)?.outputSchema), `${name} totalResults`).toMatch(
        /does not change it/i,
      );
    }

    // A tokenized keyword that matched nothing is annotated rather than silently empty.
    expect(find('nvd_search_cves')?.description).toMatch(
      /every whitespace-separated token must be present[\s\S]*copy-on-write/,
    );
    // A product name usually has no CPE entry, so a CPE filter is not a product-name search.
    expect(descriptionOf(find('nvd_search_cves')?.inputSchema, 'keyword')).toMatch(
      /Most product names have no CPE entry of their own/,
    );

    // An `eventName` filter is forwarded verbatim and matched case-insensitively; a name NVD does
    // not recognise answers 404 instead of returning an empty page.
    const eventName = descriptionOf(find('nvd_get_cve_history')?.inputSchema, 'eventName');
    expect(eventName).toMatch(/forwarded upstream/i);
    expect(eventName).toMatch(/case-insensitively/i);
    expect(eventName).toContain('UPSTREAM_BAD_RESPONSE');

    // The rejection event is "CVE Rejected", not "Rejected", and the bare word answers 404. The
    // recognised names are listed so a rejected value can be corrected without another probe.
    expect(find('nvd_get_cve_history')?.description).toMatch(
      /prefix is part of an event name[\s\S]*still has a change history/,
    );
    expect(descriptionOf(find('nvd_get_cve_history')?.inputSchema, 'eventName')).toMatch(
      /Names this tool has seen returned:[\s\S]*"CVE Rejected"/,
    );

    // Each feed names the single marker it emits, so it cannot be misread against the enum list.
    expect(find('nvd_get_recent_cves')?.description).toMatch(
      /always reports meta\.ordering as "published_desc"/,
    );
    expect(find('nvd_get_modified_cves')?.description).toMatch(
      /always reports[\s\S]*"last_modified_desc"/,
    );
    expect(find('nvd_get_cve_history')?.description).toMatch(
      /always reports[\s\S]*"change_created_asc"/,
    );

    // The CPE match tool states its pageSize ceiling; the cursor parameter states the binding to it.
    expect(find('nvd_search_cpe_matches')?.description).toMatch(/pageSize accepts up to 100 rows/);
    expect(descriptionOf(find('nvd_search_cpe_matches')?.inputSchema, 'cursor')).toMatch(
      /bound to those values/,
    );

    // Near-identical builds are distinguished by titles, not by the version token alone.
    expect(find('nvd_get_cpe')?.description).toMatch(
      /rc1-rc1[\s\S]*confirm the intended one from its titles/,
    );
    // `deprecated: false` is an assertion by NVD, and an active entry carries no relations.
    expect(find('nvd_get_cpe')?.description).toMatch(
      /active statement by NVD[\s\S]*empty deprecatedBy and deprecates/,
    );

    // Enumerating one product's criteria without reading a configuration tree is a documented,
    // verified capability: a partial version in `matchStringSearch` acts as a product/version filter.
    expect(find('nvd_search_cpe_matches')?.description).toMatch(
      /partial version therefore enumerates criteria[\s\S]*without reading a whole configuration tree/,
    );
    expect(find('nvd_get_cve')?.description).toMatch(
      /enumerate its criteria instead[\s\S]*cpe:2\.3:a:apache:log4j:\*/,
    );

    // The dictionary pattern narrows to a single build, and `keyword` is loose by comparison.
    expect(find('nvd_search_cpes')?.description).toMatch(
      /adding a version narrows it[\s\S]*cpe:2\.3:a:apache:log4j:2\.0:rc1:\*/,
    );
    expect(descriptionOf(find('nvd_search_cpes')?.inputSchema, 'keyword')).toMatch(
      /loose text match[\s\S]*use cpeMatchString to target one build/,
    );

    // A severity-only `cvss` filter still needs `version`, which is worth spelling out.
    const cvss = properties(find('nvd_search_cves')?.inputSchema)['cvss'] as
      | Record<string, unknown>
      | undefined;
    expect(descriptionOf(cvss, 'version')).toMatch(
      /a record can carry a 2\.0 and a 3\.1 score at once/,
    );

    // The CPE search distinguishes the upstream total from what the local filter removed.
    expect(find('nvd_search_cpes')?.description).toMatch(
      /meta\.filteredOut reports how many entries the local filter removed/,
    );

    // Nearby dictionary builds carry look-alike titles, so the description tells a caller to copy
    // the criteria string verbatim and compare the returned name rather than trusting the title.
    expect(find('nvd_search_cpes')?.description).toMatch(
      /look-alike titles[\s\S]*compare the returned cpeName[\s\S]*instead of trusting the title/,
    );

    // A metadata-only page still carries the walk cursor, which a pure metadata check ignores.
    expect(descriptionOf(find('nvd_search_cves')?.inputSchema, 'metaOnly')).toMatch(
      /ignore them for a pure metadata check/,
    );
  });
});

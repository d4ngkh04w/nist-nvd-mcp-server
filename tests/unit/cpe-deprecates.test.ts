import { describe, expect, it } from 'vitest';

import { mapCpeItem } from '../../src/infrastructure/nvd/mappers/cpe-mapper.js';
import { nvdCpeResponseSchema } from '../../src/infrastructure/nvd/schemas.js';
import { cpeItem, cpeResponse } from '../helpers/fixtures.js';

describe('CPE deprecates mapping', () => {
  it('keeps deprecates from the upstream payload with an uppercased cpeNameId', () => {
    const response = nvdCpeResponseSchema.parse(
      cpeResponse([
        cpeItem({
          deprecates: [
            {
              cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
              cpeNameId: 'b8f16312-24fa-4bec-b1df-a44c0cf6b36c',
            },
          ],
        }),
      ]),
    );
    const product = response.products[0];
    if (product === undefined) {
      throw new Error('Expected the parsed CPE response to contain one product');
    }

    const mapped = mapCpeItem(product.cpe);

    expect(mapped.deprecates).toEqual([
      {
        cpeName: 'cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*',
        cpeNameId: 'B8F16312-24FA-4BEC-B1DF-A44C0CF6B36C',
      },
    ]);
  });

  it('defaults deprecates to an empty array when the payload omits the field', () => {
    const response = nvdCpeResponseSchema.parse(cpeResponse([cpeItem()]));
    const product = response.products[0];
    if (product === undefined) {
      throw new Error('Expected the parsed CPE response to contain one product');
    }

    const mapped = mapCpeItem(product.cpe);

    expect(mapped.deprecates).toEqual([]);
  });
});

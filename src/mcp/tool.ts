import type { ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

import type { ToolContext } from './tool-context.js';

/**
 * Uniform tool definition.
 *
 * `defineTool` keeps the handler fully typed (input/output inferred from the zod raw shapes) while
 * the registry only sees `AnyToolDefinition`, and it re-parses both the input and the output at
 * runtime so a handler can never leak a payload that does not match the published schema.
 */
export type AnyToolDefinition = {
  name: string;
  title: string;
  description: string;
  inputShape: z.ZodRawShape;
  outputShape: z.ZodRawShape;
  annotations: ToolAnnotations;
  execute: (input: unknown, ctx: ToolContext) => Promise<Record<string, unknown>>;
};

export function defineTool<S extends z.ZodRawShape, O extends z.ZodRawShape>(definition: {
  name: string;
  title: string;
  description: string;
  inputShape: S;
  outputShape: O;
  annotations?: ToolAnnotations;
  execute: (
    input: z.infer<z.ZodObject<S>>,
    ctx: ToolContext,
  ) => Promise<z.infer<z.ZodObject<O>>>;
}): AnyToolDefinition {
  const inputSchema = z.object(definition.inputShape);
  const outputSchema = z.object(definition.outputShape);

  return {
    name: definition.name,
    title: definition.title,
    description: definition.description,
    inputShape: definition.inputShape,
    outputShape: definition.outputShape,
    annotations: definition.annotations ?? {},
    execute: async (rawInput, ctx) => {
      const input = inputSchema.parse(rawInput) as z.infer<z.ZodObject<S>>;
      const output = await definition.execute(input, ctx);
      return outputSchema.parse(output) as Record<string, unknown>;
    },
  };
}

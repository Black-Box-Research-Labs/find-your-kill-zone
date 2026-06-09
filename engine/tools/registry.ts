export type Language = string;

export interface ForensicTool<TContext = unknown, TResult = unknown> {
  name: string;
  languages: Language[];
  execute(context: TContext): Promise<TResult> | TResult;
  parseOutput?: (raw: string) => unknown;
}

export class ToolRegistry<TContext = unknown> {
  private readonly tools: ForensicTool<TContext, unknown>[] = [];

  register(tool: ForensicTool<TContext, unknown>): void {
    if (this.tools.some((t) => t.name === tool.name)) {
      throw new Error(`Tool already registered: ${tool.name}`);
    }
    this.tools.push(tool);
  }

  list(): readonly ForensicTool<TContext, unknown>[] {
    return this.tools.slice();
  }
}

/**
 * Creates a new ToolRegistry configured for the specified context type.
 *
 * @returns A fresh ToolRegistry instance parameterized by `TContext`
 */
export function createToolRegistry<
  TContext = unknown,
>(): ToolRegistry<TContext> {
  return new ToolRegistry<TContext>();
}
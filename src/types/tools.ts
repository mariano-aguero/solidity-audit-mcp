/**
 * Tool Types and Registry
 *
 * Type-safe tool registration and execution for MCP servers.
 * Provides a registry pattern for managing tools with schema validation.
 */

import { z } from "zod";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Result } from "./result.js";
import { ok, err } from "./result.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

/**
 * A tool handler function.
 */
export type ToolHandler<TInput, TOutput> = (input: TInput) => Promise<TOutput>;

/**
 * Configuration for the execute function.
 */
export interface ExecuteConfig {
  /** Whether to log execution details */
  logging?: boolean;
  /** Timeout in milliseconds */
  timeout?: number;
}

/**
 * Result of tool execution.
 */
export interface ToolExecutionResult {
  success: boolean;
  content: string;
  executionTime: number;
  error?: string;
}

/**
 * Definition of a tool including its schema and handler.
 */
export interface ToolDefinition<TInput = unknown, TOutput = unknown> {
  /** Unique name for the tool */
  name: string;
  /** Human-readable description */
  description: string;
  /** Zod schema for input validation */
  schema: z.ZodSchema<TInput>;
  /** The handler function */
  handler: ToolHandler<TInput, TOutput>;
  /** Optional custom serializer for output */
  serialize?: (output: TOutput) => string;
  /** Optional timeout override */
  timeout?: number;
}

// ============================================================================
// Tool Registry
// ============================================================================

/**
 * Registry for managing MCP tools.
 *
 * @example
 * ```ts
 * const registry = new ToolRegistry();
 *
 * registry.register({
 *   name: "analyze_contract",
 *   description: "Analyze a Solidity contract",
 *   schema: z.object({ contractPath: z.string() }),
 *   handler: async (input) => { ... }
 * });
 *
 * const tools = registry.getTools(); // For ListTools
 * const result = await registry.execute("analyze_contract", args);
 * ```
 */
export class ToolRegistry {
  private readonly tools = new Map<string, ToolDefinition>();

  /**
   * Register a new tool.
   *
   * @param definition - The tool definition
   * @throws Error if a tool with the same name is already registered
   */
  register<TInput, TOutput>(definition: ToolDefinition<TInput, TOutput>): void {
    if (this.tools.has(definition.name)) {
      throw new Error(`Tool "${definition.name}" is already registered`);
    }

    this.tools.set(definition.name, definition as ToolDefinition);
    logger.debug("Tool registered", { name: definition.name });
  }

  /**
   * Unregister a tool.
   *
   * @param name - The tool name
   * @returns True if the tool was removed
   */
  unregister(name: string): boolean {
    const removed = this.tools.delete(name);
    if (removed) {
      logger.debug("Tool unregistered", { name });
    }
    return removed;
  }

  /**
   * Check if a tool is registered.
   *
   * @param name - The tool name
   */
  has(name: string): boolean {
    return this.tools.has(name);
  }

  /**
   * Get a tool definition by name.
   *
   * @param name - The tool name
   */
  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  /**
   * Get all registered tool names.
   */
  getNames(): string[] {
    return Array.from(this.tools.keys());
  }

  /**
   * Get all tools in MCP Tool format for ListTools response.
   */
  getTools(): Tool[] {
    return Array.from(this.tools.values()).map((def) => ({
      name: def.name,
      description: def.description,
      inputSchema: zodToJsonSchema(def.schema),
    }));
  }

  /**
   * Execute a tool by name with the given arguments.
   *
   * @param name - The tool name
   * @param args - The tool arguments (will be validated)
   * @param config - Optional execution configuration
   * @returns A Result containing the execution result or error
   */
  async execute(
    name: string,
    args: unknown,
    config: ExecuteConfig = {}
  ): Promise<Result<ToolExecutionResult, Error>> {
    const startTime = Date.now();
    const definition = this.tools.get(name);

    if (!definition) {
      return err(new Error(`Unknown tool: ${name}`));
    }

    // Validate input
    const parseResult = definition.schema.safeParse(args);
    if (!parseResult.success) {
      const issues = parseResult.error.issues
        .map((i) => `${i.path.join(".")}: ${i.message}`)
        .join("; ");
      return err(new Error(`Validation error: ${issues}`));
    }

    const input = parseResult.data;

    if (config.logging !== false) {
      logger.info(`Executing tool: ${name}`, { args: input });
    }

    try {
      // Execute with optional timeout
      let output: unknown;
      const timeout = config.timeout ?? definition.timeout;

      if (timeout) {
        output = await executeWithTimeout(definition.handler(input), timeout);
      } else {
        output = await definition.handler(input);
      }

      // Serialize output
      const content = definition.serialize
        ? definition.serialize(output)
        : typeof output === "string"
          ? output
          : JSON.stringify(output, null, 2);

      const executionTime = Date.now() - startTime;

      if (config.logging !== false) {
        logger.info(`Tool completed: ${name}`, { executionTime });
      }

      return ok({
        success: true,
        content,
        executionTime,
      });
    } catch (error) {
      const executionTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      if (config.logging !== false) {
        logger.error(`Tool failed: ${name}`, { error: errorMessage, executionTime });
      }

      return ok({
        success: false,
        content: `Error: ${errorMessage}`,
        executionTime,
        error: errorMessage,
      });
    }
  }

  /**
   * Get the count of registered tools.
   */
  get size(): number {
    return this.tools.size;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * JSON Schema type for MCP tools.
 */
interface JsonSchema {
  type: "object";
  properties?: Record<string, object>;
  required?: string[];
  [key: string]: unknown;
}

/**
 * Convert a Zod schema to JSON Schema format for MCP.
 * This is a simplified conversion for common cases.
 */
function zodToJsonSchema(schema: z.ZodSchema): JsonSchema {
  // Use zod's built-in JSON schema generation if available
  // For now, we'll use a simple approach for common types

  if (schema instanceof z.ZodObject) {
    const shape = schema.shape as Record<string, z.ZodType>;
    const properties: Record<string, object> = {};
    const required: string[] = [];

    for (const [key, value] of Object.entries(shape)) {
      properties[key] = zodTypeToJsonSchema(value) as object;

      // Check if required (not optional)
      if (!(value instanceof z.ZodOptional) && !(value instanceof z.ZodDefault)) {
        required.push(key);
      }
    }

    return {
      type: "object",
      properties,
      ...(required.length > 0 ? { required } : {}),
    };
  }

  return { type: "object" };
}

function zodTypeToJsonSchema(zodType: z.ZodType): Record<string, unknown> {
  if (zodType instanceof z.ZodString) {
    const result: Record<string, unknown> = { type: "string" };
    if (zodType.description) {
      result["description"] = zodType.description;
    }
    return result;
  }

  if (zodType instanceof z.ZodNumber) {
    const result: Record<string, unknown> = { type: "number" };
    if (zodType.description) {
      result["description"] = zodType.description;
    }
    return result;
  }

  if (zodType instanceof z.ZodBoolean) {
    const result: Record<string, unknown> = { type: "boolean" };
    if (zodType.description) {
      result["description"] = zodType.description;
    }
    return result;
  }

  if (zodType instanceof z.ZodArray) {
    return {
      type: "array",
      items: zodTypeToJsonSchema(zodType.element),
    };
  }

  if (zodType instanceof z.ZodEnum) {
    return {
      type: "string",
      enum: zodType.options,
    };
  }

  if (zodType instanceof z.ZodOptional) {
    return zodTypeToJsonSchema(zodType.unwrap());
  }

  if (zodType instanceof z.ZodDefault) {
    const inner = zodTypeToJsonSchema(zodType._def.innerType as z.ZodType);
    inner["default"] = zodType._def.defaultValue();
    return inner;
  }

  if (zodType instanceof z.ZodObject) {
    return zodToJsonSchema(zodType);
  }

  // Fallback
  return { type: "string" };
}

/**
 * Execute a promise with a timeout.
 */
async function executeWithTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  const controller = new AbortController();

  const timeoutPromise = new Promise<never>((_, reject) => {
    const id = setTimeout(() => {
      controller.abort();
      reject(new Error(`Operation timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    // Clean up timeout if promise resolves first
    promise.finally(() => clearTimeout(id));
  });

  return Promise.race([promise, timeoutPromise]);
}

// ============================================================================
// Default Registry Instance
// ============================================================================

/**
 * Default global tool registry.
 */
export const toolRegistry = new ToolRegistry();

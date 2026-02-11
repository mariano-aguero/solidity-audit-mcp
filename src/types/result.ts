/**
 * Result Type
 *
 * A type-safe way to handle operations that can fail without throwing exceptions.
 * Inspired by Rust's Result<T, E> type.
 *
 * Benefits:
 * - Explicit error handling at compile time
 * - No unexpected exceptions
 * - Easy to chain operations
 * - Better type inference
 */

// ============================================================================
// Core Types
// ============================================================================

/**
 * Represents a successful result containing a value.
 */
export interface Ok<T> {
  readonly ok: true;
  readonly value: T;
}

/**
 * Represents a failed result containing an error.
 */
export interface Err<E> {
  readonly ok: false;
  readonly error: E;
}

/**
 * A Result type that can be either Ok<T> or Err<E>.
 *
 * @example
 * ```ts
 * function divide(a: number, b: number): Result<number, string> {
 *   if (b === 0) {
 *     return err("Division by zero");
 *   }
 *   return ok(a / b);
 * }
 *
 * const result = divide(10, 2);
 * if (result.ok) {
 *   console.log(result.value); // 5
 * } else {
 *   console.error(result.error);
 * }
 * ```
 */
export type Result<T, E = Error> = Ok<T> | Err<E>;

// ============================================================================
// Constructors
// ============================================================================

/**
 * Create a successful Result.
 *
 * @param value - The success value
 * @returns An Ok result
 */
export function ok<T>(value: T): Ok<T> {
  return { ok: true, value };
}

/**
 * Create a failed Result.
 *
 * @param error - The error value
 * @returns An Err result
 */
export function err<E>(error: E): Err<E> {
  return { ok: false, error };
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Check if a Result is Ok.
 */
export function isOk<T, E>(result: Result<T, E>): result is Ok<T> {
  return result.ok;
}

/**
 * Check if a Result is Err.
 */
export function isErr<T, E>(result: Result<T, E>): result is Err<E> {
  return !result.ok;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Map a function over a successful Result.
 *
 * @param result - The Result to map over
 * @param fn - The function to apply to the success value
 * @returns A new Result with the mapped value or the original error
 */
export function map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
  if (result.ok) {
    return ok(fn(result.value));
  }
  return result;
}

/**
 * Map a function over a failed Result.
 *
 * @param result - The Result to map over
 * @param fn - The function to apply to the error
 * @returns A new Result with the original value or mapped error
 */
export function mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F> {
  if (!result.ok) {
    return err(fn(result.error));
  }
  return result;
}

/**
 * Chain Results together (flatMap/bind).
 *
 * @param result - The Result to chain
 * @param fn - The function that returns a new Result
 * @returns The chained Result
 */
export function andThen<T, U, E>(
  result: Result<T, E>,
  fn: (value: T) => Result<U, E>
): Result<U, E> {
  if (result.ok) {
    return fn(result.value);
  }
  return result;
}

/**
 * Provide a fallback for a failed Result.
 *
 * @param result - The Result to provide fallback for
 * @param fn - The function that returns a fallback Result
 * @returns The original Result if Ok, or the fallback
 */
export function orElse<T, E, F>(
  result: Result<T, E>,
  fn: (error: E) => Result<T, F>
): Result<T, F> {
  if (!result.ok) {
    return fn(result.error);
  }
  return result;
}

/**
 * Unwrap a Result, throwing if it's an error.
 *
 * @param result - The Result to unwrap
 * @returns The success value
 * @throws The error if Result is Err
 */
export function unwrap<T, E>(result: Result<T, E>): T {
  if (result.ok) {
    return result.value;
  }
  throw result.error;
}

/**
 * Unwrap a Result with a default value.
 *
 * @param result - The Result to unwrap
 * @param defaultValue - The default value if Err
 * @returns The success value or default
 */
export function unwrapOr<T, E>(result: Result<T, E>, defaultValue: T): T {
  if (result.ok) {
    return result.value;
  }
  return defaultValue;
}

/**
 * Unwrap a Result with a default value from a function.
 *
 * @param result - The Result to unwrap
 * @param fn - The function to call if Err
 * @returns The success value or computed default
 */
export function unwrapOrElse<T, E>(result: Result<T, E>, fn: (error: E) => T): T {
  if (result.ok) {
    return result.value;
  }
  return fn(result.error);
}

// ============================================================================
// Async Utilities
// ============================================================================

/**
 * Wrap an async function that might throw into a Result.
 *
 * @param fn - The async function to wrap
 * @returns A Result containing the value or error
 *
 * @example
 * ```ts
 * const result = await tryCatch(async () => {
 *   const response = await fetch(url);
 *   return response.json();
 * });
 * ```
 */
export async function tryCatch<T>(fn: () => Promise<T>): Promise<Result<T, Error>> {
  try {
    const value = await fn();
    return ok(value);
  } catch (error) {
    return err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * Wrap a sync function that might throw into a Result.
 *
 * @param fn - The function to wrap
 * @returns A Result containing the value or error
 */
export function tryCatchSync<T>(fn: () => T): Result<T, Error> {
  try {
    const value = fn();
    return ok(value);
  } catch (error) {
    return err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * Combine multiple Results into a single Result.
 * If all Results are Ok, returns Ok with an array of values.
 * If any Result is Err, returns the first Err.
 *
 * @param results - Array of Results to combine
 * @returns A single Result with all values or the first error
 */
export function all<T, E>(results: Array<Result<T, E>>): Result<T[], E> {
  const values: T[] = [];
  for (const result of results) {
    if (!result.ok) {
      return result;
    }
    values.push(result.value);
  }
  return ok(values);
}

/**
 * Collect Results from an async iterator.
 *
 * @param results - Array of Result promises
 * @returns A single Result with all values or the first error
 */
export async function allAsync<T, E>(
  results: Array<Promise<Result<T, E>>>
): Promise<Result<T[], E>> {
  const resolved = await Promise.all(results);
  return all(resolved);
}

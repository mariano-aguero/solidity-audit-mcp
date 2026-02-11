/**
 * Path Validation Utilities
 *
 * Security utilities for validating and sanitizing file paths.
 * Prevents path traversal attacks and ensures paths are within expected boundaries.
 */

import { resolve, relative, isAbsolute, normalize, basename, extname } from "node:path";
import { access, stat } from "node:fs/promises";
import { type Result, ok, err } from "../types/result.js";

// ============================================================================
// Types
// ============================================================================

export interface PathValidationError {
  code: "PATH_TRAVERSAL" | "NOT_FOUND" | "NOT_FILE" | "INVALID_EXTENSION" | "ACCESS_DENIED";
  message: string;
  path: string;
}

export interface ValidatedPath {
  absolute: string;
  relative: string;
  basename: string;
  extension: string;
}

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate and resolve a contract path, ensuring it's within the project root.
 *
 * @param contractPath - The path to validate (absolute or relative)
 * @param projectRoot - The project root directory
 * @returns A Result with the validated path info or an error
 *
 * @example
 * ```ts
 * const result = validateContractPath("./contracts/Token.sol", "/project");
 * if (result.ok) {
 *   console.log(result.value.absolute); // /project/contracts/Token.sol
 * }
 * ```
 */
export function validateContractPath(
  contractPath: string,
  projectRoot: string
): Result<ValidatedPath, PathValidationError> {
  // Normalize and resolve paths
  const normalizedRoot = normalize(resolve(projectRoot));
  const absolutePath = isAbsolute(contractPath)
    ? normalize(contractPath)
    : normalize(resolve(normalizedRoot, contractPath));

  // Check for path traversal
  const relativePath = relative(normalizedRoot, absolutePath);

  if (relativePath.startsWith("..") || isAbsolute(relativePath)) {
    return err({
      code: "PATH_TRAVERSAL",
      message: `Path "${contractPath}" attempts to access files outside project root`,
      path: contractPath,
    });
  }

  // Check for null bytes (common in path traversal attacks)
  if (contractPath.includes("\0") || absolutePath.includes("\0")) {
    return err({
      code: "PATH_TRAVERSAL",
      message: "Path contains null bytes",
      path: contractPath,
    });
  }

  return ok({
    absolute: absolutePath,
    relative: relativePath,
    basename: basename(absolutePath),
    extension: extname(absolutePath),
  });
}

/**
 * Validate that a path exists and is a file (not a directory).
 *
 * @param filePath - The absolute path to check
 * @returns A Result indicating success or the error
 */
export async function validateFileExists(
  filePath: string
): Promise<Result<true, PathValidationError>> {
  try {
    await access(filePath);
  } catch {
    return err({
      code: "NOT_FOUND",
      message: `File not found: ${filePath}`,
      path: filePath,
    });
  }

  try {
    const stats = await stat(filePath);
    if (!stats.isFile()) {
      return err({
        code: "NOT_FILE",
        message: `Path is not a file: ${filePath}`,
        path: filePath,
      });
    }
  } catch {
    return err({
      code: "ACCESS_DENIED",
      message: `Cannot access file: ${filePath}`,
      path: filePath,
    });
  }

  return ok(true);
}

/**
 * Validate that a file has an allowed extension.
 *
 * @param filePath - The file path to check
 * @param allowedExtensions - Array of allowed extensions (with dot, e.g., [".sol", ".vy"])
 * @returns A Result indicating success or the error
 */
export function validateExtension(
  filePath: string,
  allowedExtensions: string[]
): Result<true, PathValidationError> {
  const ext = extname(filePath).toLowerCase();

  if (!allowedExtensions.includes(ext)) {
    return err({
      code: "INVALID_EXTENSION",
      message: `Invalid file extension "${ext}". Allowed: ${allowedExtensions.join(", ")}`,
      path: filePath,
    });
  }

  return ok(true);
}

/**
 * Fully validate a Solidity contract path.
 * Combines path traversal check, existence check, and extension check.
 *
 * @param contractPath - The path to validate
 * @param projectRoot - The project root directory
 * @returns A Result with the validated path info or an error
 */
export async function validateSolidityPath(
  contractPath: string,
  projectRoot: string
): Promise<Result<ValidatedPath, PathValidationError>> {
  // Step 1: Validate path is within project
  const pathResult = validateContractPath(contractPath, projectRoot);
  if (!pathResult.ok) {
    return pathResult;
  }

  // Step 2: Validate extension
  const extResult = validateExtension(pathResult.value.absolute, [".sol"]);
  if (!extResult.ok) {
    return extResult;
  }

  // Step 3: Validate file exists
  const existsResult = await validateFileExists(pathResult.value.absolute);
  if (!existsResult.ok) {
    return existsResult;
  }

  return pathResult;
}

/**
 * Sanitize a filename by removing potentially dangerous characters.
 *
 * @param filename - The filename to sanitize
 * @returns The sanitized filename
 */
export function sanitizeFilename(filename: string): string {
  return filename
    .replace(/\0/g, "") // Remove null bytes
    .replace(/\.\./g, "") // Remove parent directory references
    .replace(/[<>:"|?*]/g, "") // Remove Windows-invalid characters
    .replace(/\//g, "_") // Replace path separators
    .replace(/\\/g, "_")
    .trim();
}

/**
 * Check if a path is safe (no traversal attempts).
 *
 * @param path - The path to check
 * @returns True if the path is safe
 */
export function isPathSafe(path: string): boolean {
  const normalized = normalize(path);

  // Check for common traversal patterns
  if (normalized.includes("..")) return false;
  if (normalized.includes("\0")) return false;

  // Check for absolute paths when relative expected
  if (isAbsolute(normalized) && !path.startsWith("/")) return false;

  return true;
}

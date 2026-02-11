#!/bin/bash
# =============================================================================
# Docker Build Script for MCP Audit Server
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

IMAGE_NAME="solidity-audit-mcp"
IMAGE_TAG="${1:-latest}"

echo "🔨 Building MCP Audit Server Docker image..."
echo "   Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

cd "$PROJECT_DIR"

# Build the image
docker build \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -f Dockerfile \
    .

echo ""
echo "✅ Build complete!"
echo ""
echo "Usage examples:"
echo ""
echo "  # Run MCP server (for Claude Desktop integration)"
echo "  docker run -i ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "  # Run CLI audit on a contract"
echo "  docker run -v \$(pwd):/contracts ${IMAGE_NAME}:${IMAGE_TAG} node dist/cli.js analyze /contracts/MyContract.sol"
echo ""
echo "  # Interactive shell with all tools"
echo "  docker run -it --entrypoint bash -v \$(pwd):/contracts ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "  # Check installed tool versions"
echo "  docker run --entrypoint bash ${IMAGE_NAME}:${IMAGE_TAG} -c 'slither --version && aderyn --version && forge --version'"

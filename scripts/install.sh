#!/bin/bash

# MCP Audit Server Installation Script
# =====================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  MCP Audit Server Installation${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to check if a command exists
check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function to print status
print_status() {
    if [ "$2" = "ok" ]; then
        echo -e "  ${GREEN}✓${NC} $1"
    elif [ "$2" = "warn" ]; then
        echo -e "  ${YELLOW}!${NC} $1"
    else
        echo -e "  ${RED}✗${NC} $1"
    fi
}

# ============================================
# Step 1: Check Node.js
# ============================================
echo -e "${BLUE}Checking prerequisites...${NC}"
echo ""

if check_command node; then
    NODE_VERSION=$(node --version)
    print_status "Node.js $NODE_VERSION" "ok"
else
    print_status "Node.js not found" "error"
    echo ""
    echo -e "${RED}Node.js 18+ is required. Install it from:${NC}"
    echo "  https://nodejs.org/"
    echo "  or using nvm: nvm install 20"
    exit 1
fi

# ============================================
# Step 2: Check optional dependencies
# ============================================
MISSING_TOOLS=()

if check_command slither; then
    SLITHER_VERSION=$(slither --version 2>&1 | head -n1)
    print_status "Slither $SLITHER_VERSION" "ok"
else
    print_status "Slither not installed (optional)" "warn"
    MISSING_TOOLS+=("slither")
fi

if check_command aderyn; then
    ADERYN_VERSION=$(aderyn --version 2>&1 | head -n1)
    print_status "Aderyn $ADERYN_VERSION" "ok"
else
    print_status "Aderyn not installed (optional)" "warn"
    MISSING_TOOLS+=("aderyn")
fi

if check_command forge; then
    FORGE_VERSION=$(forge --version 2>&1 | head -n1)
    print_status "Foundry (forge) $FORGE_VERSION" "ok"
else
    print_status "Foundry not installed (optional)" "warn"
    MISSING_TOOLS+=("forge")
fi

if check_command solc; then
    SOLC_VERSION=$(solc --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    print_status "solc $SOLC_VERSION" "ok"
else
    print_status "solc not installed (required by Slither)" "warn"
    MISSING_TOOLS+=("solc")
fi

echo ""

# ============================================
# Step 3: Show installation instructions for missing tools
# ============================================
if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Some optional tools are not installed.${NC}"
    echo -e "${YELLOW}The server will work but with limited functionality.${NC}"
    echo ""

    for tool in "${MISSING_TOOLS[@]}"; do
        case $tool in
            slither)
                echo -e "${BLUE}To install Slither:${NC}"
                echo "  pip install slither-analyzer"
                echo "  # or: pipx install slither-analyzer"
                echo ""
                ;;
            aderyn)
                echo -e "${BLUE}To install Aderyn:${NC}"
                echo "  cargo install aderyn"
                echo "  # or: curl -L https://raw.githubusercontent.com/Cyfrin/aderyn/dev/cyfrinup/install | bash && cyfrinup"
                echo ""
                ;;
            forge)
                echo -e "${BLUE}To install Foundry:${NC}"
                echo "  curl -L https://foundry.paradigm.xyz | bash"
                echo "  foundryup"
                echo ""
                ;;
            solc)
                echo -e "${BLUE}To install solc:${NC}"
                echo "  pip install solc-select"
                echo "  solc-select install 0.8.20"
                echo "  solc-select use 0.8.20"
                echo ""
                ;;
        esac
    done
fi

# ============================================
# Step 4: Install npm dependencies and build
# ============================================
echo -e "${BLUE}Installing dependencies...${NC}"
cd "$SCRIPT_DIR"
npm install

echo ""
echo -e "${BLUE}Building project...${NC}"
npm run build

echo ""
print_status "Build completed successfully" "ok"

# ============================================
# Step 5: Optionally configure Claude MCP
# ============================================
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Configuration${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

CLAUDE_CONFIG_DIR="$HOME/.claude"
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/mcp.json"

echo "Do you want to add this server to your global Claude MCP configuration?"
echo "This will modify: $CLAUDE_CONFIG_FILE"
echo ""
read -p "Add to global config? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Create .claude directory if it doesn't exist
    mkdir -p "$CLAUDE_CONFIG_DIR"

    # Create or update mcp.json
    if [ -f "$CLAUDE_CONFIG_FILE" ]; then
        # File exists, need to merge
        echo -e "${YELLOW}Existing config found. Backing up to mcp.json.backup${NC}"
        cp "$CLAUDE_CONFIG_FILE" "$CLAUDE_CONFIG_FILE.backup"

        # Check if jq is available for proper JSON merging
        if check_command jq; then
            # Use jq to merge
            jq --arg path "$SCRIPT_DIR/dist/index.js" '.mcpServers.audit = {
                "command": "node",
                "args": [$path],
                "env": {
                    "REPORT_FORMAT": "markdown",
                    "SEVERITY_THRESHOLD": "low",
                    "TIMEOUT": "180"
                }
            }' "$CLAUDE_CONFIG_FILE.backup" > "$CLAUDE_CONFIG_FILE"
            print_status "Configuration updated using jq" "ok"
        else
            echo -e "${YELLOW}jq not found. Please manually add the following to $CLAUDE_CONFIG_FILE:${NC}"
            echo ""
            echo "  \"audit\": {"
            echo "    \"command\": \"node\","
            echo "    \"args\": [\"$SCRIPT_DIR/dist/index.js\"],"
            echo "    \"env\": {"
            echo "      \"REPORT_FORMAT\": \"markdown\","
            echo "      \"SEVERITY_THRESHOLD\": \"low\","
            echo "      \"TIMEOUT\": \"180\""
            echo "    }"
            echo "  }"
            echo ""
        fi
    else
        # Create new config file
        cat > "$CLAUDE_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "audit": {
      "command": "node",
      "args": ["$SCRIPT_DIR/dist/index.js"],
      "env": {
        "REPORT_FORMAT": "markdown",
        "SEVERITY_THRESHOLD": "low",
        "TIMEOUT": "180"
      }
    }
  }
}
EOF
        print_status "Configuration created at $CLAUDE_CONFIG_FILE" "ok"
    fi
else
    echo ""
    echo "Skipped global configuration."
    echo ""
    echo "To configure manually, add to $CLAUDE_CONFIG_FILE:"
    echo ""
    cat << EOF
{
  "mcpServers": {
    "audit": {
      "command": "node",
      "args": ["$SCRIPT_DIR/dist/index.js"],
      "env": {
        "REPORT_FORMAT": "markdown",
        "SEVERITY_THRESHOLD": "low",
        "TIMEOUT": "180"
      }
    }
  }
}
EOF
fi

# ============================================
# Step 6: Done!
# ============================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "The MCP Audit Server is ready to use."
echo ""
echo "Available tools:"
echo "  - analyze_contract    Full security analysis"
echo "  - get_contract_info   Extract contract metadata"
echo "  - check_vulnerabilities   SWC pattern matching"
echo "  - run_tests           Execute forge tests"
echo "  - generate_report     Format audit reports"
echo ""
echo "For project-level config, copy .mcp.json.example to your project's .mcp.json"
echo ""

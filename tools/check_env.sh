#!/bin/bash
# tools/check_env.sh — Environment validation script for MS-1

set -e

echo "=== NES2Native Environment Check ==="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_command() {
    local cmd=$1
    local name=$2
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $name: $(command -v "$cmd")"
        return 0
    else
        echo -e "${RED}✗${NC} $name: NOT FOUND"
        return 1
    fi
}

check_version() {
    local cmd=$1
    local name=$2
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $name version: $($cmd $3 2>&1 | head -1)"
        return 0
    else
        echo -e "${RED}✗${NC} $name: NOT FOUND"
        return 1
    fi
}

# Check Python
check_version python3 "Python" "--version"

# Check FCEUX
if command -v fceux &> /dev/null; then
    echo -e "${GREEN}✓${NC} FCEUX: $(command -v fceux)"
    if fceux --help 2>&1 | grep -q "loadlua"; then
        echo -e "${GREEN}  ✓${NC} --loadlua support confirmed"
    else
        echo -e "${YELLOW}  ⚠${NC} --loadlua support not detected"
    fi
else
    echo -e "${RED}✗${NC} FCEUX: NOT FOUND"
fi

# Check Graphviz
check_version dot "Graphviz (dot)" "-V"

# Check Java
if command -v java &> /dev/null; then
    java_version=$(java -version 2>&1 | head -1)
    echo -e "${GREEN}✓${NC} Java: $java_version"
else
    echo -e "${RED}✗${NC} Java: NOT FOUND (required for Ghidra)"
    echo -e "${YELLOW}  → Install from: https://adoptium.net/temurin/releases/${NC}"
fi

# Check Ghidra
if [ -f ".env" ]; then
    source .env
    if [ -n "$GHIDRA_HOME" ] && [ -f "$GHIDRA_HOME/support/analyzeHeadless" ]; then
        echo -e "${GREEN}✓${NC} Ghidra: $GHIDRA_HOME"
        if command -v java &> /dev/null; then
            echo -e "${GREEN}  ✓${NC} analyzeHeadless found"
        else
            echo -e "${YELLOW}  ⚠${NC} analyzeHeadless found but Java missing"
        fi
    else
        echo -e "${RED}✗${NC} Ghidra: GHIDRA_HOME not set or invalid"
    fi
else
    echo -e "${YELLOW}⚠${NC} .env file not found (run: cp .env.example .env)"
fi

# Check Claude Code CLI (optional)
if command -v claude &> /dev/null; then
    echo -e "${GREEN}✓${NC} Claude CLI: $(command -v claude)"
else
    echo -e "${YELLOW}⚠${NC} Claude CLI: NOT FOUND (optional for LLM agents)"
fi

echo ""
echo "=== Summary ==="
echo "Required for MS-2 (CDL collection): FCEUX"
echo "Required for MS-4+ (Ghidra): Java 17+, GHIDRA_HOME"
echo "Required for MS-8+ (LLM agents): Claude/codex CLI"
echo ""

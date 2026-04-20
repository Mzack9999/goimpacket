#!/bin/bash
# Copyright 2026 Google LLC
# Copyright 2026 Mzack9999
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# goimpacket installer
# Builds all tools and installs them as goimpacket-<toolname> on your PATH
#

set -e

# Default install directory
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BUILD_DIR="./bin"
TOOL_PREFIX="goimpacket"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --prefix DIR    Install to DIR (default: /usr/local/bin)"
    echo "  --build-only    Build but don't install"
    echo "  --uninstall     Remove installed goimpacket tools"
    echo "  -h, --help      Show this help"
    echo ""
    echo "Environment:"
    echo "  INSTALL_DIR     Same as --prefix (default: /usr/local/bin)"
}

build_only=false
uninstall=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --build-only)
            build_only=true
            shift
            ;;
        --uninstall)
            uninstall=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Uninstall mode
if $uninstall; then
    echo "Removing ${TOOL_PREFIX} tools from ${INSTALL_DIR}..."
    count=0
    for f in "${INSTALL_DIR}"/${TOOL_PREFIX}-*; do
        if [ -f "$f" ]; then
            echo "  removing $(basename "$f")"
            rm -f "$f"
            ((count++))
        fi
    done
    if [ $count -eq 0 ]; then
        echo "No ${TOOL_PREFIX} tools found in ${INSTALL_DIR}"
    else
        echo -e "${GREEN}Removed ${count} tools${NC}"
    fi
    exit 0
fi

# Check dependencies
if ! command -v go &>/dev/null; then
    echo -e "${RED}Error: go is not installed or not in PATH${NC}"
    echo "Install Go from https://go.dev/dl/"
    exit 1
fi

# GCC is required for the proxychains hooks in pkg/transport (cgo).
# libpcap headers are NOT required: the cgo-free github.com/Mzack9999/gopacket
# fork loads libpcap dynamically at runtime via purego.
if ! command -v gcc &>/dev/null; then
    echo -e "${RED}Error: gcc is not installed${NC}"
    echo "Install with: apt install build-essential (Debian/Ubuntu) or yum install gcc (RHEL/CentOS)"
    exit 1
fi

# Determine script directory (where go.mod lives)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f go.mod ]; then
    echo -e "${RED}Error: go.mod not found. Run this script from the goimpacket directory.${NC}"
    exit 1
fi

# Discover tools
tools=($(ls tools/))
total=${#tools[@]}

echo "goimpacket installer"
echo "  Tools:   ${total}"
echo "  Build:   ${BUILD_DIR}/"
if ! $build_only; then
    echo "  Install: ${INSTALL_DIR}/"
fi
echo ""

# Linker flags differ between platforms:
#  - Linux (GNU ld): statically link libgcc so the binary doesn't depend on a
#    specific libgcc.so on the target system.
#  - macOS (clang/ld64): doesn't support -static-libgcc; use the default
#    external linker with no extra flags.
case "$(uname -s)" in
    Linux)
        LDFLAGS='-linkmode external -extldflags "-static-libgcc"'
        ;;
    Darwin)
        LDFLAGS=''
        ;;
    *)
        LDFLAGS=''
        ;;
esac

# Build
echo "Building ${total} tools..."
mkdir -p "${BUILD_DIR}"

failed=0
for tool in "${tools[@]}"; do
    echo -n "  ${tool}... "
    if [ -n "$LDFLAGS" ]; then
        err=$(CGO_ENABLED=1 go build -o "${BUILD_DIR}/${tool}" \
            -ldflags "$LDFLAGS" \
            "./tools/${tool}" 2>&1)
    else
        err=$(CGO_ENABLED=1 go build -o "${BUILD_DIR}/${tool}" \
            "./tools/${tool}" 2>&1)
    fi
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}ok${NC}"
    else
        echo -e "${RED}failed${NC}"
        echo "$err" | sed 's/^/      /'
        failed=$((failed + 1))
    fi
done

if [ $failed -gt 0 ]; then
    echo -e "\n${RED}${failed} tool(s) failed to build${NC}"
    exit 1
fi

echo -e "\n${GREEN}Built ${total}/${total} tools successfully${NC}"
echo -e "${YELLOW}Note:${NC} the sniff and split tools dynamically load libpcap at runtime."
echo "      Install a libpcap shared library to use them:"
echo "        Debian/Ubuntu/Kali: apt install libpcap0.8"
echo "        RHEL/CentOS:        yum install libpcap"
echo "        macOS:              brew install libpcap"

if $build_only; then
    echo ""
    echo "Binaries are in ${BUILD_DIR}/"
    exit 0
fi

# Install
echo ""
echo "Installing to ${INSTALL_DIR}/ as ${TOOL_PREFIX}-<toolname>..."

# Check write permissions
if [ ! -w "${INSTALL_DIR}" ]; then
    echo -e "${YELLOW}Note: ${INSTALL_DIR} requires elevated permissions${NC}"
    echo "Re-running install step with sudo..."
    SUDO="sudo"
else
    SUDO=""
fi

for tool in "${tools[@]}"; do
    if [ ! -f "${BUILD_DIR}/${tool}" ]; then
        continue
    fi
    # Normalize tool name: lowercase, replace special chars with hyphens
    normalized=$(echo "$tool" | tr '[:upper:]' '[:lower:]' | tr '_' '-')
    dest="${INSTALL_DIR}/${TOOL_PREFIX}-${normalized}"
    $SUDO cp "${BUILD_DIR}/${tool}" "$dest"
    $SUDO chmod +x "$dest"
done

echo -e "${GREEN}Installed ${total} tools to ${INSTALL_DIR}/${NC}"
echo ""
echo "Tools are available as:"
echo "  ${TOOL_PREFIX}-secretsdump, ${TOOL_PREFIX}-smbclient, ${TOOL_PREFIX}-psexec, etc."
echo ""
echo "Run '${TOOL_PREFIX}-<tool> -h' for help on any tool."
echo "To uninstall: $0 --uninstall"

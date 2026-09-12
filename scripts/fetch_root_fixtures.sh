#!/usr/bin/env bash
#
# Fetch root hints (named.root) and root zone (root.zone) files from IANA / InterNIC.
# Used for local testing and CI workflow cache population.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES_DIR="${WORKSPACE_ROOT}/tests/fixtures"

NAMED_ROOT_URL="https://www.internic.net/domain/named.root"
ROOT_ZONE_GZ_URL="https://www.internic.net/domain/root.zone.gz"
ROOT_ZONE_URL="https://www.internic.net/domain/root.zone"
ROOT_ANCHORS_URL="https://data.iana.org/root-anchors/root-anchors.xml"

FORCE=false
HINTS_ONLY=false
ZONE_ONLY=false
ANCHORS_ONLY=false
MAX_AGE_DAYS=7

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [DEST_DIR]

Downloads IANA root hints, root zone, and root anchors XML files for integration testing.

Arguments:
    DEST_DIR            Target directory for downloaded fixtures
                        (default: tests/fixtures)

Options:
    --force, -f         Re-download files even if they already exist
    --max-age-days N    Re-download if file is older than N days (default: 7, 0 to disable)
    --hints-only        Only download named.root (~3.3 KB)
    --zone-only         Only download root.zone (~1 MB compressed, ~2.2 MB uncompressed)
    --anchors-only      Only download root-anchors.xml (~2 KB)
    --help, -h          Show this help message
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f)
            FORCE=true
            shift
            ;;
        --max-age-days)
            MAX_AGE_DAYS="$2"
            shift 2
            ;;
        --hints-only)
            HINTS_ONLY=true
            shift
            ;;
        --zone-only)
            ZONE_ONLY=true
            shift
            ;;
        --anchors-only)
            ANCHORS_ONLY=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            FIXTURES_DIR="$1"
            shift
            ;;
    esac
done

mkdir -p "${FIXTURES_DIR}"

DOWNLOADED=false

is_file_fresh() {
    local file="$1"
    local max_days="$2"
    if [[ ! -f "${file}" ]] || [[ ! -s "${file}" ]]; then
        return 1
    fi
    if [[ "${max_days}" -le 0 ]]; then
        return 0
    fi
    # In POSIX find, -mtime +N matches files modified more than (N+1) * 24h ago.
    # To consider files older than max_days stale, test with (max_days - 1).
    local threshold=$((max_days - 1))
    if [[ -n "$(find "${file}" -mtime +"${threshold}" 2>/dev/null)" ]]; then
        return 1
    fi
    return 0
}

fetch_named_root() {
    local target="${FIXTURES_DIR}/named.root"
    if [[ -f "${target}" ]] && [[ "${FORCE}" != "true" ]]; then
        if is_file_fresh "${target}" "${MAX_AGE_DAYS}"; then
            echo "Root hints already present and fresh at ${target} (use --force to re-download)."
            return 0
        else
            echo "Root hints at ${target} is older than ${MAX_AGE_DAYS} days; re-downloading..."
        fi
    fi

    echo "Downloading root hints from ${NAMED_ROOT_URL}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${NAMED_ROOT_URL}" -o "${target}.tmp"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${NAMED_ROOT_URL}" -O "${target}.tmp"
    else
        echo "Error: Neither curl nor wget is available." >&2
        exit 1
    fi

    # Verify download is non-empty and looks like a hints file
    if ! grep -q "ROOT-SERVERS.NET" "${target}.tmp" 2>/dev/null; then
        echo "Error: Downloaded named.root did not match expected root servers content." >&2
        rm -f "${target}.tmp"
        exit 1
    fi

    mv "${target}.tmp" "${target}"
    DOWNLOADED=true
    echo "Saved root hints to ${target} ($(wc -c < "${target}" | tr -d ' ') bytes)."
}

fetch_root_zone() {
    local target="${FIXTURES_DIR}/root.zone"
    if [[ -f "${target}" ]] && [[ "${FORCE}" != "true" ]]; then
        if is_file_fresh "${target}" "${MAX_AGE_DAYS}"; then
            echo "Root zone already present and fresh at ${target} (use --force to re-download)."
            return 0
        else
            echo "Root zone at ${target} is older than ${MAX_AGE_DAYS} days; re-downloading..."
        fi
    fi

    echo "Downloading root zone from ${ROOT_ZONE_GZ_URL}..."
    local gz_tmp="${FIXTURES_DIR}/root.zone.gz.tmp"
    local downloaded=false

    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL "${ROOT_ZONE_GZ_URL}" -o "${gz_tmp}" 2>/dev/null; then
            downloaded=true
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q "${ROOT_ZONE_GZ_URL}" -O "${gz_tmp}" 2>/dev/null; then
            downloaded=true
        fi
    fi

    if [[ "${downloaded}" == "true" ]] && command -v gzip >/dev/null 2>&1; then
        echo "Decompressing root zone..."
        gzip -dc "${gz_tmp}" > "${target}.tmp"
        rm -f "${gz_tmp}"
    else
        echo "Falling back to uncompressed download from ${ROOT_ZONE_URL}..."
        rm -f "${gz_tmp}"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "${ROOT_ZONE_URL}" -o "${target}.tmp"
        elif command -v wget >/dev/null 2>&1; then
            wget -q "${ROOT_ZONE_URL}" -O "${target}.tmp"
        else
            echo "Error: Neither curl nor wget is available." >&2
            exit 1
        fi
    fi

    # Verify download is non-empty and contains root SOA
    if ! grep -q "a.root-servers.net." "${target}.tmp" 2>/dev/null; then
        echo "Error: Downloaded root.zone did not match expected root zone content." >&2
        rm -f "${target}.tmp"
        exit 1
    fi

    mv "${target}.tmp" "${target}"
    DOWNLOADED=true
    echo "Saved root zone to ${target} ($(wc -c < "${target}" | tr -d ' ') bytes, $(wc -l < "${target}" | tr -d ' ') lines)."
}

fetch_root_anchors() {
    local target="${FIXTURES_DIR}/root-anchors.xml"
    if [[ -f "${target}" ]] && [[ "${FORCE}" != "true" ]]; then
        if is_file_fresh "${target}" "${MAX_AGE_DAYS}"; then
            echo "Root anchors XML already present and fresh at ${target} (use --force to re-download)."
            return 0
        else
            echo "Root anchors XML at ${target} is older than ${MAX_AGE_DAYS} days; re-downloading..."
        fi
    fi

    echo "Downloading root anchors XML from ${ROOT_ANCHORS_URL}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${ROOT_ANCHORS_URL}" -o "${target}.tmp"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${ROOT_ANCHORS_URL}" -O "${target}.tmp"
    else
        echo "Error: Neither curl nor wget is available." >&2
        exit 1
    fi

    # Verify download is non-empty and contains TrustAnchor
    if ! grep -q "TrustAnchor" "${target}.tmp" 2>/dev/null; then
        echo "Error: Downloaded root-anchors.xml did not match expected XML content." >&2
        rm -f "${target}.tmp"
        exit 1
    fi

    mv "${target}.tmp" "${target}"
    DOWNLOADED=true
    echo "Saved root anchors XML to ${target} ($(wc -c < "${target}" | tr -d ' ') bytes)."
}

if [[ "${ANCHORS_ONLY}" == "true" ]]; then
    fetch_root_anchors
elif [[ "${ZONE_ONLY}" == "true" ]]; then
    fetch_root_zone
elif [[ "${HINTS_ONLY}" == "true" ]]; then
    fetch_named_root
else
    fetch_named_root
    fetch_root_zone
    fetch_root_anchors
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "updated=${DOWNLOADED}" >> "${GITHUB_OUTPUT}"
fi

echo "Fixture download complete."

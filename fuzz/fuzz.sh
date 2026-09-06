#!/usr/bin/env bash
# Runs all rustdns cargo-fuzz targets with recommended limits and defaults.
#
# Usage:
#   ./fuzz/fuzz.sh                 # Runs each target for 15 minutes (900s)
#   ./fuzz/fuzz.sh 1800            # Runs each target for 30 minutes (1800s)
#   ./fuzz/fuzz.sh 60 from-slice   # Runs only from-slice for 60s
#   ./fuzz/fuzz.sh --cmin          # Minifies corpora for all targets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGETS=("from-slice" "encode" "from-str" "json" "edns" "rname")

DURATION="${1:-900}" # Default to 15 minutes (900s) per target
SPECIFIC_TARGET="${2:-}"

# Calculate sensible default jobs (half of physical CPU cores, min 1, max 4)
NUM_CORES=2
if [[ "$OSTYPE" == "darwin"* ]]; then
    NUM_CORES=$(sysctl -n hw.ncpu || echo 2)
elif command -v nproc &>/dev/null; then
    NUM_CORES=$(nproc || echo 2)
fi
DEFAULT_JORES=$(( NUM_CORES / 2 ))
if [[ "$DEFAULT_JORES" -lt 1 ]]; then
    DEFAULT_JORES=1
elif [[ "$DEFAULT_JORES" -gt 4 ]]; then
    DEFAULT_JORES=4
fi

JOBS="${FUZZ_JOBS:-$DEFAULT_JORES}"
MAX_LEN="${FUZZ_MAX_LEN:-4096}"
TIMEOUT="${FUZZ_TIMEOUT:-5}"
RSS_LIMIT_MB="${FUZZ_RSS_LIMIT_MB:-2048}"

if [[ "$DURATION" == "--cmin" ]]; then
    echo "==> Minifying corpus for all targets..."
    for target in "${TARGETS[@]}"; do
        echo "--> Minifying ${target}..."
        (cd "${REPO_ROOT}" && cargo +nightly fuzz cmin "${target}")
    done
    echo "==> Done minifying!"
    exit 0
fi

if [[ -n "$SPECIFIC_TARGET" ]]; then
    TARGETS=("$SPECIFIC_TARGET")
fi

echo "=========================================================="
echo "rustdns Fuzz Runner"
echo "  Targets:      ${TARGETS[*]}"
echo "  Duration:     ${DURATION}s per target"
echo "  Workers/Jobs: ${JOBS}"
echo "  Max Len:      ${MAX_LEN} bytes"
echo "  Timeout:      ${TIMEOUT}s"
echo "  Memory limit: ${RSS_LIMIT_MB} MB"
echo "=========================================================="

CRASH_FOUND=0

for target in "${TARGETS[@]}"; do
    echo ""
    echo "===> Running target: ${target} for ${DURATION}s..."
    echo ""

    mkdir -p "${SCRIPT_DIR}/corpus/${target}"
    mkdir -p "${SCRIPT_DIR}/artifacts/${target}"

    # Record any existing artifact files before the run
    ARTIFACT_DIR="${SCRIPT_DIR}/artifacts/${target}"
    BEFORE_COUNT=$(find "${ARTIFACT_DIR}" -type f 2>/dev/null | wc -l | tr -d ' ')

    set +e
    (cd "${REPO_ROOT}" && cargo +nightly fuzz run "${target}" -- \
        -max_len="${MAX_LEN}" \
        -timeout="${TIMEOUT}" \
        -rss_limit_mb="${RSS_LIMIT_MB}" \
        -max_total_time="${DURATION}" \
        -jobs="${JOBS}" \
        -workers="${JOBS}")
    RUN_EXIT=$?
    set -e

    AFTER_COUNT=$(find "${ARTIFACT_DIR}" -type f 2>/dev/null | wc -l | tr -d ' ')

    if [[ "$AFTER_COUNT" -gt "$BEFORE_COUNT" ]] || [[ "$RUN_EXIT" -ne 0 ]]; then
        echo ""
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "CRASH / BUG DETECTED for target '${target}'!"
        echo "Artifacts in: ${ARTIFACT_DIR}"
        find "${ARTIFACT_DIR}" -type f
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        CRASH_FOUND=1
    else
        echo "===> No crashes found for target: ${target}"
    fi

    # Auto-run cmin if corpus exists and has files
    CORPUS_DIR="${SCRIPT_DIR}/corpus/${target}"
    if [[ -d "${CORPUS_DIR}" ]] && [ -n "$(find "${CORPUS_DIR}" -type f -print -quit 2>/dev/null || find "${CORPUS_DIR}" -type f | head -n 1)" ]; then
        echo "===> Auto-minifying corpus for '${target}'..."
        (cd "${REPO_ROOT}" && cargo +nightly fuzz cmin "${target}")
        echo "===> Minification complete for '${target}'."
    fi
done

echo ""
echo "=========================================================="
if [[ "$CRASH_FOUND" -ne 0 ]]; then
    echo "SUMMARY: One or more targets encountered crashes."
    echo "Check fuzz/artifacts/<target>/ for crash reproductions."
    exit 1
else
    echo "SUMMARY: All fuzz runs completed successfully. No crashes found."
    echo "All corpora were automatically minified."
fi
echo "=========================================================="

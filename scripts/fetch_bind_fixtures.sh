#!/usr/bin/env bash
# Fetch an immutable BIND checkzone corpus; normal tests never access the network.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${ROOT}/tests/bind_checkzone.yaml"
DEST="${ROOT}/tests/fixtures/bind-checkzone"
FORCE=false

for arg in "$@"; do
    case "${arg}" in
        --force|-f) FORCE=true ;;
        --help|-h)
            echo "Usage: $0 [--force] [DEST_DIR]"
            exit 0 ;;
        -*) echo "Unknown option: ${arg}" >&2; exit 1 ;;
        *) DEST="${arg}" ;;
    esac
done

REVISION="$(sed -n 's/^revision: //p' "${CONFIG}")"
if [[ ! "${REVISION}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Invalid pinned revision in ${CONFIG}" >&2
    exit 1
fi
if [[ -e "${DEST}/zones" && ! -f "${DEST}/REVISION" ]]; then
    echo "Refusing to replace an unmarked fixture directory: ${DEST}/zones" >&2
    exit 1
fi
COMPLETE=true
while IFS= read -r name; do
    if [[ ! -s "${DEST}/zones/${name}" ]]; then COMPLETE=false; fi
done < <(sed -n 's/^  - {file: \([^,]*\),.*/\1/p' "${CONFIG}")
if [[ "${FORCE}" == false && -f "${DEST}/REVISION" ]] &&
    [[ "$(cat "${DEST}/REVISION")" == "${REVISION}" ]] &&
    [[ "${COMPLETE}" == true ]] &&
    [[ -s "${DEST}/zones/good1.db" && -s "${DEST}/LICENSE" &&
       -s "${DEST}/COPYRIGHT" && -s "${DEST}/tests.sh" ]]; then
    echo "BIND checkzone fixtures already present at ${REVISION}."
    exit 0
fi

mkdir -p "${DEST}"
TEMP="$(mktemp -d "${DEST}/.download.XXXXXX")"
trap 'rm -rf -- "${TEMP}"' EXIT
URL="https://codeload.github.com/isc-projects/bind9/tar.gz/${REVISION}"
echo "Fetching BIND checkzone fixtures at ${REVISION}..."
curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    "${URL}" -o "${TEMP}/bind.tar.gz"
PREFIX="bind9-${REVISION}"
tar -xzf "${TEMP}/bind.tar.gz" -C "${TEMP}" \
    "${PREFIX}/bin/tests/system/checkzone/zones" \
    "${PREFIX}/bin/tests/system/checkzone/tests.sh" \
    "${PREFIX}/LICENSE" "${PREFIX}/COPYRIGHT"

# Only replace the corpus after the complete download and extraction succeeded.
if [[ -d "${DEST}/zones" ]]; then
    rm -rf -- "${DEST}/zones"
fi
mv "${TEMP}/${PREFIX}/bin/tests/system/checkzone/zones" "${DEST}/zones"
cp "${TEMP}/${PREFIX}/bin/tests/system/checkzone/tests.sh" "${DEST}/tests.sh"
cp "${TEMP}/${PREFIX}/LICENSE" "${TEMP}/${PREFIX}/COPYRIGHT" "${DEST}/"
printf '%s\n' "${REVISION}" > "${DEST}/REVISION"
echo "BIND fixtures ready at ${DEST}."

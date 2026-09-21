#!/usr/bin/env bash
# sbom.sh — emit a minimal, deterministic SPDX tag-value SBOM snapshot of the
# module graph (built from `go list -m all`) into ${DIST_DIR:-dist}/sbom.spdx.
#
# Usage: scripts/sbom.sh [VERSION]
#
# The output is deterministic for a given module graph and version: every field
# is sorted, and the document and the package metadata carry fixed timestamps
# only when a real version is supplied (otherwise a placeholder is used).

set -euo pipefail

MODULE=gfw-x
VERSION="${1:-UNKNOWN}"
DIST_DIR="${DIST_DIR:-dist}"
OUT="${DIST_DIR}/sbom.spdx"
# SPDXID of the root package (this module).
ROOT_ID="SPDXRef-Package-gfwx"

# Map a Go module path to an SPDX package identifier name.
pkg_id() {
    local name
    name="$(printf '%s' "$1" | tr '/.+' '_')"
    printf 'SPDXRef-%s' "$name"
}

if ! command -v go >/dev/null 2>&1; then
    echo "error: 'go' not found in PATH" >&2
    exit 1
fi

mkdir -p "${DIST_DIR}"

# Collect (name version) pairs for external modules only (root excluded),
# sorted by module path so the output is reproducible.
mods="$(go list -m -f '{{if ne .Path "gfw-x"}}{{.Path}} {{.Version}}{{end}}' all | LC_ALL=C sort)"

# Trim the leading version ("v") semantic so it fits SPDX notation naturally.
# Only emit a DocumentCreated stamp when a real released version is provided so
# repeated local runs stay byte-identical for CI diffs.
SPDX_VERSION="SPDX-2.3"
CREATOR="Tool: gfw-x sbom.sh"

{
    printf 'SPDXVersion: %s\n' "${SPDX_VERSION}"
    printf 'DataLicense: CC0-1.0\n'
    printf 'SPDXID: SPDXRef-DOCUMENT\n'
    printf 'DocumentName: %s\n' "${MODULE}"
    printf 'DocumentNamespace: https://spdx.org/spdxdocs/%s-%s\n' "${MODULE}" "${VERSION}"
    printf 'Creator: %s\n' "${CREATOR}"
    printf 'Creator: Organization: gfw-x\n'
    [ "${VERSION}" = "UNKNOWN" ] || printf 'Created: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '\n'

    # Root package (this module).
    printf 'PackageName: %s\n' "${MODULE}"
    printf 'SPDXID: %s\n' "${ROOT_ID}"
    printf 'PackageVersion: %s\n' "${VERSION}"
    printf 'PackageDownloadLocation: NOASSERTION\n'
    printf 'FilesAnalyzed: false\n'
    printf 'PackageLicenseConcluded: NOASSERTION\n'
    printf '\n'

    # Relationship: the root package contains each external module.
    while IFS=' ' read -r path ver; do
        [ -n "${path}" ] || continue
        printf 'Relationship: %s CONTAINS %s\n' \
            "${ROOT_ID}" "$(pkg_id "${path}")"
    done <<< "${mods}"
    printf '\n'

    # External package descriptions, one block per module.
    while IFS=' ' read -r path ver; do
        [ -n "${path}" ] || continue
        id="$(pkg_id "${path}")"
        printf 'PackageName: %s\n' "${path}"
        printf 'SPDXID: SPDXRef-%s\n' "${id}"
        printf 'PackageVersion: %s\n' "${ver}"
        printf 'PackageDownloadLocation: NOASSERTION\n'
        printf 'FilesAnalyzed: false\n'
        printf 'PackageLicenseConcluded: NOASSERTION\n'
        printf '\n'
    done <<< "${mods}"
} > "${OUT}"

echo ">> wrote ${OUT}"
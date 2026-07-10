#!/usr/bin/env bash
set -euo pipefail

# Validate the nftables backend in an isolated Linux VM without touching the
# default production table. This creates a short-lived test table and set,
# inserts one documentation-reserved IP with timeout, verifies membership, and
# removes the test table on exit.
#
# Usage:
#   sudo ./scripts/validate_nftables_vm.sh
# Optional env:
#   AEGIS_NFT_TEST_FAMILY=inet
#   AEGIS_NFT_TEST_TABLE=aegis_guard_vmtest
#   AEGIS_NFT_TEST_IP=203.0.113.254

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo/root inside an isolated Linux VM." >&2
  exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
  echo "nft executable not found. Install nftables first." >&2
  exit 1
fi

FAMILY="${AEGIS_NFT_TEST_FAMILY:-inet}"
TABLE="${AEGIS_NFT_TEST_TABLE:-aegis_guard_vmtest}"
IP="${AEGIS_NFT_TEST_IP:-203.0.113.254}"
SET="block_in_v4"
CHAIN="input"

cleanup() {
  nft delete table "$FAMILY" "$TABLE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

nft add table "$FAMILY" "$TABLE"
nft add chain "$FAMILY" "$TABLE" "$CHAIN" '{ type filter hook input priority -10; policy accept; }'
nft add set "$FAMILY" "$TABLE" "$SET" '{ type ipv4_addr; flags timeout; }'
nft add rule "$FAMILY" "$TABLE" "$CHAIN" ip saddr "@$SET" counter drop comment aegis_vmtest_block_in_v4
nft add element "$FAMILY" "$TABLE" "$SET" "{ $IP timeout 60s }"

LISTING="$(nft list set "$FAMILY" "$TABLE" "$SET")"
if [[ "$LISTING" != *"$IP"* ]]; then
  echo "nftables validation failed: element not found in set" >&2
  echo "$LISTING" >&2
  exit 1
fi

echo "nftables VM validation PASS"
echo "Created and verified: $FAMILY $TABLE $SET contains $IP timeout 60s"
echo "Temporary table will be removed automatically."

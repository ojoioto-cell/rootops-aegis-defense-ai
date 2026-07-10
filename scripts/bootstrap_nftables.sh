#!/usr/bin/env bash
set -euo pipefail

# Optional bootstrap. v0.1.3 can create these objects automatically when actual enforcement runs.
# This script is useful for preflight validation.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo/root" >&2
  exit 1
fi

TABLE="${AEGIS_NFT_TABLE:-aegis_guard}"
FAMILY="${AEGIS_NFT_FAMILY:-inet}"

nft add table "$FAMILY" "$TABLE" 2>/dev/null || true
nft add chain "$FAMILY" "$TABLE" input '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || true
nft add chain "$FAMILY" "$TABLE" output '{ type filter hook output priority -10; policy accept; }' 2>/dev/null || true

for version in v4 v6; do
  if [[ "$version" == "v4" ]]; then
    type="ipv4_addr"
    ipkw="ip"
  else
    type="ipv6_addr"
    ipkw="ip6"
  fi
  nft add set "$FAMILY" "$TABLE" "block_in_${version}" "{ type ${type}; flags timeout; }" 2>/dev/null || true
  nft add set "$FAMILY" "$TABLE" "block_out_${version}" "{ type ${type}; flags timeout; }" 2>/dev/null || true
  nft add set "$FAMILY" "$TABLE" "rate_limit_${version}" "{ type ${type}; flags timeout; }" 2>/dev/null || true
  nft add rule "$FAMILY" "$TABLE" input "$ipkw" saddr "@block_in_${version}" counter drop comment "aegis_block_in_${version}" 2>/dev/null || true
  nft add rule "$FAMILY" "$TABLE" output "$ipkw" daddr "@block_out_${version}" counter drop comment "aegis_block_out_${version}" 2>/dev/null || true
  nft add rule "$FAMILY" "$TABLE" input "$ipkw" saddr "@rate_limit_${version}" tcp flags syn limit rate over 20/second counter drop comment "aegis_rate_limit_${version}" 2>/dev/null || true
done

echo "nftables Aegis table is ready: ${FAMILY} ${TABLE}"
nft list table "$FAMILY" "$TABLE"

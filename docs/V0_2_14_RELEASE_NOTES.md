# Aegis v0.2.14 All-in-One Check Patch

v0.2.14 includes v0.2.13 and adds a single beginner-friendly check workflow.

## Added

- `scripts/aegis_all_in_one_check.sh`
  - Runs post-install validation
  - Runs GPT/API connectivity diagnosis
  - Runs secrets check
  - Runs self-protection integrity check
  - Checks services and central API health
  - Captures nftables state and rejects wildcard outbound blocks
  - Runs actions/incidents/reasoning-ledger CLI checks
  - Runs AI Duel Demo proof generation
  - Runs Proof Report generation
  - Runs expired-action cleanup dry-run
  - Writes `/var/lib/aegis/checks/all_in_one_<timestamp>/summary.json`

## Installer behavior

`sudo ./scripts/all_in_one_competition_install.sh` now ends by calling:

```bash
sudo /opt/aegis-linux-defense-agent/scripts/aegis_all_in_one_check.sh
```

The installer sets `AEGIS_AUTO_RESET_BASELINE=1` only during approved post-install validation so self-protection baseline refresh is safe after installation/config generation.

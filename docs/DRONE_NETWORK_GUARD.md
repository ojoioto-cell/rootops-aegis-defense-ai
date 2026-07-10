# Aegis v0.2.9 Drone Network Guard

Aegis v0.2.9 protects both ordinary Unix/Linux servers and Linux-based drone network nodes such as GCS hosts, companion computers, edge gateways, and control servers.

## Safety boundary

Drone Network Guard is defense-only. It never sends MAVLink, ROS2, flight-control, mission, parameter-write, arming, disarming, takeoff, landing, RC override, or vehicle-control traffic. It passively collects evidence and uses the existing Policy Gate + nftables enforcement path to block or rate-limit untrusted network sources.

## Protected locations

- GCS Linux host or laptop
- Companion computer: Jetson, Raspberry Pi, x86 Linux
- Edge gateway or mesh gateway
- Drone control/telemetry server
- Linux router/relay node

Flight-controller firmware and RF/jamming protection are outside the scope of this agent.

## Detections

- Unauthorized GCS/source IP on MAVLink ports
- MAVLink command-class message from untrusted source
- Mission/parameter change attempt from untrusted source
- Heartbeat spoofing or sysid/component anomaly
- MAVLink flood or telemetry abuse
- ROS2/DDS discovery probe/flood
- C2 outbound and host compromise evidence from the existing Linux guard

## Default ports

MAVLink: 14550-14555 and 5760-5763 by default.
ROS2/DDS: 7400-7403, 7410-7413, and 11811 by default.

## All-in-one competition install

```bash
sudo AEGIS_GCS_IPS="192.168.13.10" \
     AEGIS_DRONE_IPS="192.168.13.20" \
     ./scripts/all_in_one_competition_install.sh
```

If `AEGIS_GCS_IPS` is omitted, the installer uses the admin allowlist as the initial GCS allowlist to avoid locking out the operator. For a real drone network, set the actual authorized GCS IPs.

## Runtime log input

The installer creates:

```text
/var/log/aegis/drone_mavlink.log
```

The passive collector can parse simple evidence lines such as:

```text
SRC=192.168.13.50 DST=192.168.13.20 DPT=14550 MAVLINK MSG=COMMAND_LONG SYSID=255 COMPID=1
SRC=192.168.13.50 DST=192.168.13.20 DPT=14550 MAVLINK MSG=PARAM_SET SYSID=255 COMPID=1
```

It also observes live `ss -tunap` output for configured MAVLink/ROS2 ports.

## Response

Untrusted MAVLink/ROS2 sources are handled through normal Local Enforcement:

- `block_ip_ttl` for unauthorized GCS or command/mission/parameter attempts
- `rate_limit_ip` for MAVLink/ROS2 flood evidence
- Existing Linux defenses for C2, suspicious process, file quarantine, and persistence disablement

## Verification

```bash
sudo /opt/aegis-linux-defense-agent/scripts/aegis_competition_status.sh
sudo nft list set inet aegis_guard block_in_v4
sudo nft list set inet aegis_guard rate_limit_v4
sudo /opt/aegis-linux-defense-agent/.venv/bin/python -m aegis_agent incidents --config /etc/aegis/agent.yaml --limit 20
```

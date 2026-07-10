# Aegis v0.2.13 Safety Patch

This release includes v0.2.12 and adds competition safety fixes:

- Network snapshot filtering rejects wildcard/listener rows such as `0.0.0.0:*`.
- Firewall enforcement rejects unsafe targets: `0.0.0.0`, `::`, loopback, multicast, link-local and broadcast.
- Policy Gate denies invalid IP targets before execution.
- Self-protection baseline is reset automatically after approved install/repair before services start.
- AI/GPT connectivity diagnostic script checks API key, time/CA issues and fallback state.
- Post-install validation checks invalid target rejection.

Private RFC1918 addresses are still allowed because competition attackers or drone nodes may use private networks.

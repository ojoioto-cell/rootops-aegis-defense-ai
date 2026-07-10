# Aegis Central Monitoring UI v0.2.3

v0.2.3 upgrades the central monitoring server from a static table view to an offline single-page control-plane UI. The local Linux agents still perform detection and enforcement; Central remains the monitoring, policy, IOC, and approval plane.

## UI pages

- **Overview**: agent online/offline status, incidents, critical incidents, action status, IOC count, pending approvals, top attack types.
- **Agents**: heartbeat inventory, version, computed online/offline state, assigned policy details.
- **Incidents**: Evidence Chain incident list and detail JSON viewer.
- **Actions**: flattened defense-action index from ingested incidents.
- **Policies**: create/update central policy and assign it to agents.
- **IOC**: create/delete central indicators.
- **Approvals**: create approval requests and approve/reject high-risk actions.

## API additions

```text
GET    /api/summary
GET    /api/agents/{agent_id}
GET    /api/incidents/{row_id}
GET    /api/actions
GET    /api/actions/{action_id}
GET    /api/policies/{policy_id}
DELETE /api/policies/{policy_id}
DELETE /api/iocs/{ioc_id}
POST   /api/approvals/{request_id}/decision
GET    /                 -> UI
GET    /dashboard        -> UI
```

## Action index

`/api/ingest` now indexes each incident's `actions[]` into `action_index`. This enables the UI and `/api/actions` to search defense actions independently from the full incident payload.

## Authentication

Start Central with an optional bearer token:

```bash
python -m aegis_central.server --host 127.0.0.1 --port 8088 --db data/central.db --token change-me
```

Read APIs remain convenient for local testing. Write APIs require:

```text
Authorization: Bearer change-me
```

The UI has a token box in the left sidebar. Save the token there before using create/delete/decision actions.

## Run

```bash
python -m aegis_central.server --host 127.0.0.1 --port 8088 --db data/central.db
# Open http://127.0.0.1:8088/dashboard
```

## Safety boundary

The UI does not directly run shell commands or enforce firewall rules. It stores policies, IOC, approvals, and incident/action records. Actual server defense remains in the Local Defense Agent through Policy Gate and Local Enforcement Layer.

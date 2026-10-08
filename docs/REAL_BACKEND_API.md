# Real Backend/API Wiring

## Scope

#8 is the HTTP integration boundary over the verified local-first components:

- #5 \`KnowledgeRAGBackend\` for knowledge ingestion and lexical-plus-relationship retrieval;
- #6 \`SituationStore\` for telemetry/event ingestion, queries, and evidence-only situation snapshots;
- #7 \`ControlledCommandGateway\` for explicitly allowlisted command execution.

The API does not duplicate business logic and does not interpret shell syntax.

## HTTP surface

\`GET /health\` performs component health/integrity checks.

Knowledge:
- \`POST /v1/knowledge/records\`
- \`GET /v1/knowledge/query\`

Telemetry:
- \`POST /v1/telemetry/events\`
- \`POST /v1/telemetry/events/batch\`
- \`GET /v1/telemetry/events\`
- \`GET /v1/telemetry/situation\`

Commands:
- \`GET /v1/commands\`
- \`POST /v1/commands/execute\`

Every response carries an \`X-Request-ID\` correlation header; supplied IDs are accepted only when they match a bounded safe token format.

## Security boundary

The API cannot define command policies. A \`ControlledCommandGateway\` must be constructed by the embedding runtime and explicitly injected into \`create_app()\`. The default local app therefore has command execution disabled.

Command requests contain only a command name and argv list. They are passed unchanged to #7, which applies exact allowlist matching, \`shell=False\`, cwd containment, environment allowlisting, timeout, and output limits.

The API has no network client, no LLM calls, no generic subprocess runner, and no automatic remediation.

## Local deployment

The default app uses \`AI_CYBER_DATA_DIR\` when set and otherwise stores SQLite databases beneath \`.ai_cyber/data\`. Keep the server bound to loopback unless a later deployment/security layer adds explicit authentication and network policy.

Example:

\`\`\`bash
uvicorn --factory ai_cyber_os.api:create_default_app --host 127.0.0.1 --port 8000
\`\`\`

The default app exposes retrieval and telemetry only. Command execution requires an embedding application to inject explicit policies.

## Test gate

FastAPI's \`TestClient\` is used for the API suite; it is designed for direct application testing and uses HTTPX. The CI job installs \`httpx\` explicitly alongside pytest. citeturn245530search0turn245530search2

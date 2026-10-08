# Controlled Command Gateway

## Scope

The #7 Controlled Command Gateway is the execution boundary for commands that later components may need to invoke. It is intentionally narrower than a generic shell runner.

Every executable path is absolute. Every command name is mapped to one immutable policy entry. Every allowed argument vector is an exact tuple already registered in that policy. There is no wildcard matching, shell string parsing, prefix matching, regex argument expansion, or arbitrary command construction.

## Execution contract

A request is represented by a command name plus an argv tuple. The gateway:

1. validates the request shape and byte limits;
2. looks up the command policy;
3. rejects anything not exactly present in the policy;
4. resolves the policy's cwd only beneath a configured workspace root;
5. passes only explicitly allowlisted environment variables;
6. executes argv directly with \`subprocess.run(..., shell=False)\`;
7. applies bounded timeout and captured-output limits;
8. returns a structured \`CommandResult\` rather than raising for a normal non-zero exit;
9. writes an execution or denial event to the #6 SituationStore when audit is configured.

Denied requests become \`alert\` telemetry. Successful or failed process launches become \`process\` telemetry. The audit payload stores SHA-256 digests and lengths for stdout/stderr rather than copying command output into the telemetry database.

## Security boundary

This layer prevents command-injection style string construction and accidental shell interpretation, but it is not an OS sandbox. A permitted executable still executes with the privileges granted by the hosting account. Filesystem isolation, syscall restrictions, network isolation, and container/VM policy belong to a later hardening layer.

The gateway also never infers that a command succeeded operationally beyond the process return code and timeout state. No security finding, remediation, or attacker attribution is generated here.

## Test gate

The #7 CI workflow compiles the gateway and exercises:

- absolute-path policy requirements;
- exact argv enforcement;
- shell-metacharacter rejection through policy mismatch;
- environment non-inheritance;
- explicit environment allowlisting;
- workspace escape prevention;
- timeout handling;
- non-zero exit handling;
- bounded returned output;
- denial/execution audit telemetry;
- deterministic policy hashing;
- regression suites for #1 through #6.

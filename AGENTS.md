# AGENTS.md

## Purpose

OpAgent is a lightweight Linux operations agent built on the pi coding agent SDK. The project is intentionally centered on safety, auditable execution, and operational tooling rather than generic coding assistance. Treat safety and auditability as part of the product design, not optional polish.

## Core design: safety first, then operations

- Default mode is read-only. The agent may inspect files, logs, system state, and metrics, but it should not make writes or destructive changes without explicit enablement.
- Write and destructive paths are guarded by `PolicyGuard` and interactive confirmation; see [src/safety/policy.ts](src/safety/policy.ts) and [src/safety/extension.ts](src/safety/extension.ts).
- The audit log is hash-chained SQLite, not an afterthought; see [src/audit/store.ts](src/audit/store.ts) and [src/audit/extension.ts](src/audit/extension.ts).
- The CLI bootstraps pi runtime, safety extensions, audit extensions, tools, and skills in [src/index.ts](src/index.ts).
- The monitoring system is a headless daemon with pluggable collectors and notifiers under [src/monitor](src/monitor).

## Module map

- [src/index.ts](src/index.ts): CLI bootstrap, config loading, extension assembly, tool registration, monitor setup, agent session creation.
- [src/config.ts](src/config.ts): configuration precedence and environment handling (`OPAGENT_*`, global `~/.op_agent/.env`, model selection).
- [src/prompt.ts](src/prompt.ts): system prompt for the operational assistant.
- [src/safety/policy.ts](src/safety/policy.ts): `PolicyGuard` logic and destructive/write path classification.
- [src/safety/patterns.ts](src/safety/patterns.ts): risk patterns and blocked commands/path rules.
- [src/safety/extension.ts](src/safety/extension.ts): `tool_call`/`user_bash` enforcement, confirm gate, command rewrite, sandbox-aware checks.
- [src/safety/sandbox.ts](src/safety/sandbox.ts): OS sandbox enforcement for `run_script`.
- [src/audit/llm.ts](src/audit/llm.ts): LLM semantic auditing and safety-level merging.
- [src/audit/store.ts](src/audit/store.ts): append-only, hash-chained SQLite store.
- [src/tools/inspect.ts](src/tools/inspect.ts): read-only inspection tools (disk/mem/cpu/net/service/logs).
- [src/tools/script.ts](src/tools/script.ts): script generation flow (`bash -n`, dry run, policy checks, confirmation, sandbox execution).
- [src/tools/destructive.ts](src/tools/destructive.ts): destructive tools, only registered when `--allow-destructive` is enabled.
- [src/monitor](src/monitor): registry, daemon, collector/notifier scaffolding and runtime.
- [src/skills/index.ts](src/skills/index.ts): built-in skills loading/indexing.
- [skills](skills): repo-local SKILL.md files for ops tasks.
- [test](test): Bun tests for policy and audit behavior.

## Working rules for code changes

1. Preserve the safety model.
   - Do not weaken default blocking rules.
   - Any write or destructive path should still flow through the guard and audit chain.

2. Prefer read-only investigation first.
   - Many operational tasks should be handled with inspection tools and logs before any corrective action.

3. Use explicit opt-ins for writes.
   - Writes require `--allow-write` and confirmation; destructive actions require `--allow-destructive` plus additional reasoning and confirmation.

4. Keep sandbox and policy semantics consistent.
   - If code alters script execution or path validation, update the related policy and tests together.

5. Favor the project conventions over generic Node/Bun advice.
   - Use Bun for runtime tasks and tests, but match the project’s safety-first operational semantics.

## Build and validation commands

- `bun test`
- `bun run typecheck`
- `bun run src/index.ts`
- `bun run build`

## Design notes to keep in mind

- The project is intentionally lightweight: one Bun process, embedded SQLite, no Redis/Mongo/Milvus in the default design.
- The validation path is not “write then fix”; it is “inspect, guard, confirm, audit, execute.”
- For monitoring and alerts, the system is designed around small headless daemons, collector plugins, and notifier plugins rather than a heavy orchestration stack.
- A large part of the value is in making unsafe actions difficult or impossible at the tool-call layer before the model can act on them.

## Relevant documents

- [README.md](README.md)
- [design.md](design.md)
- [monitor_design.md](monitor_design.md)
- [coding_desc.md](coding_desc.md)
- [CLAUDE.md](CLAUDE.md)

This file is intentionally concise and project-specific. Add more detail only when it materially affects how an agent should safely operate in this repo.

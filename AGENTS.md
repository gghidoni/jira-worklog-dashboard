# Agent Instructions (AGENTS.md)

This repository contains a small Go web service (Docker-friendly) plus `opencode.jsonc`.
Use this document as:
- A quick checklist for figuring out how to build/lint/test as the codebase grows
- Default code-style and engineering conventions to follow until the repo defines stricter ones

If you add or discover a real build system, update the **Commands** section first.

## Repo-Specific Rules Found

- OpenCode config: `opencode.jsonc`
  - Model configured: `openai/gpt-5.2`
  - Permissions: broad allow, with `external_directory` denied; `.env` files are readable

### Cursor / Copilot Rules

- No Cursor rules found (`.cursor/rules/` or `.cursorrules`)
- No Copilot instructions found (`.github/copilot-instructions.md`)

## Commands

Go + Docker tooling is available.

### Go

- Build: `go build ./...`
- Test (compiles packages): `go test ./...`
- Run locally:
  - `JIRA_BASE_URL=... JIRA_EMAIL=... JIRA_API_TOKEN=... go run ./cmd/jira-worklog-dashboard`

### Docker

- Build image: `docker build -t jira-worklog-dashboard .`
- Run: `docker run --rm -p 8080:8080 --env-file .env jira-worklog-dashboard`
- Compose: `cp .env.example .env && docker compose up --build`

### Discovery Flow (Do This First)

1. Identify the toolchain:
   - Node: `package.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lockb`
   - Python: `pyproject.toml`, `requirements.txt`, `poetry.lock`
   - Go: `go.mod`
   - Rust: `Cargo.toml`
2. List available tasks:
   - Node: `npm run` / `pnpm -r run` / `yarn run`
   - Python: check `pyproject.toml` scripts/tools
3. Run the fastest check first (format/lint) before longer test suites.

### Recommended Defaults (If You Add These Toolchains)

Pick one stack and make it canonical; do not accumulate parallel linters/test runners.

#### Node (npm/pnpm/yarn)

- Install: `npm ci` (or `pnpm i --frozen-lockfile` / `yarn --frozen-lockfile`)
- Build: `npm run build`
- Lint: `npm run lint`
- Format: `npm run format` (and `npm run format:check` if supported)
- Test (all): `npm test` or `npm run test`
- Test (single file):
  - Jest: `npx jest path/to/test.test.ts`
  - Vitest: `npx vitest run path/to/test.test.ts`
- Test (single test by name):
  - Jest: `npx jest -t "test name"`
  - Vitest: `npx vitest run -t "test name"`

#### Python

- Create venv: `python -m venv .venv && source .venv/bin/activate`
- Install (pip): `python -m pip install -r requirements.txt`
- Install (uv): `uv sync`
- Lint:
  - Ruff: `ruff check .`
  - Flake8: `flake8`
- Format:
  - Ruff: `ruff format .`
  - Black: `black .`
- Typecheck: `mypy .` or `pyright`
- Test (all): `pytest`
- Test (single file): `pytest path/to/test_file.py`
- Test (single test): `pytest path/to/test_file.py -k "test_name_substring"`

#### Go

- Build: `go build ./...`
- Format: `gofmt -w .`
- Lint (if added): `golangci-lint run`
- Test (all): `go test ./...`
- Test (single package): `go test ./path/to/pkg`
- Test (single test): `go test ./path/to/pkg -run '^TestName$'`

#### Rust

- Build: `cargo build`
- Format: `cargo fmt`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test (all): `cargo test`
- Test (single test): `cargo test test_name_substring`

## Code Style Guidelines

Until the codebase specifies otherwise, follow these conventions.

### General

- Prefer clarity over cleverness; optimize for maintainability and debuggability.
- Keep functions small and single-purpose; avoid deeply nested control flow.
- Write self-documenting code; add comments only for non-obvious intent or constraints.
- Avoid global state; prefer explicit dependency injection (parameters/constructors).

### Formatting

- Use an auto-formatter and do not hand-align.
- Keep line length reasonable (aim ~100 chars unless the formatter enforces otherwise).
- Prefer trailing commas where supported to reduce diff churn.

### Imports

- Group imports in this order (with blank lines between groups):
  1) standard library
  2) third-party
  3) internal (project) modules
- Avoid circular imports; refactor shared types/utilities into neutral modules.
- Do not use wildcard/glob imports except for tightly controlled re-exports.

### Naming

- Use meaningful names; prefer domain terms over implementation terms.
- Keep abbreviations rare and consistent (e.g., `id`, `url`, `api`).
- Boolean names should read like predicates: `isReady`, `hasAccess`, `canRetry`.
- Collections: use plural nouns (`users`, `errorMessages`).

### Types (When Applicable)

- Prefer explicit public API types; internal inference is fine if it stays readable.
- Do not use "any"/dynamic types unless you fence them with validation.
- Keep type definitions close to usage; extract shared types only when reused.

### Error Handling

- Prefer typed/structured errors over string matching.
- Attach context at boundaries (I/O, network, persistence) and preserve root causes.
- Avoid swallowing errors; if you intentionally ignore, do so explicitly and document why.
- For user-facing errors: sanitize messages; do not leak secrets or internals.

### Logging

- Log with structure (fields) when possible; avoid unstructured concatenation.
- Do not log secrets (tokens, passwords, session cookies, PII).
- Use consistent levels: debug (dev), info (expected), warn (recoverable), error (actionable).

### Tests

- Prefer deterministic tests; avoid time-based sleeps (use fakes/mocks/clock control).
- Name tests by behavior: "does X when Y".
- Arrange/Act/Assert structure; keep assertions focused.
- For bug fixes: add a regression test that fails before the fix.

### API / IO Boundaries

- Validate external inputs at the boundary; keep core logic operating on trusted types.
- Keep side effects at the edges; core functions should be pure where practical.
- Prefer idempotent operations and explicit retries with backoff where needed.

### Security

- Never commit secrets; prefer `.env.example` for documentation.
- Treat all external data as untrusted; validate and sanitize.
- Prefer least privilege for any credentials/config that get introduced.

## Updating This File

When real tooling exists, replace placeholders with the exact commands used by this repo
and add any repo-specific conventions (folder structure, modules, testing patterns, etc.).

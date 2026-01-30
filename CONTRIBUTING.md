# Contributing

Thanks for contributing!

## Development setup

Prereqs:
- Go (see `go.mod` for the target version)
- Docker (optional)

Commands:

```bash
gofmt -w cmd internal
go test ./...
go run ./cmd/jira-worklog-dashboard
```

## Pull requests

- Keep changes small and focused.
- Don’t commit secrets (`.env`, tokens, credentials).
- If you change behavior, update `README.md`.

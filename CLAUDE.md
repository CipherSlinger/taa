# TAA Project Guidelines

## Common Commands
- Build TAA: `go build -o bin/taa ./cmd/taa`
- Build Platform-Mock: `go build -o bin/platform-mock ./cmd/platform-mock`
- Run tests: `go test ./...`

## Coding and Comment Guidelines
- **Code comments**: Must use English comments only.

## Planning and Documentation (Plan & Spec)
- All solution designs (spec) and implementation plans (plan) must be saved uniformly in `.claude/specs/` and `.claude/plans/`, strictly forbidden to be stored in `docs/`.

## Agent and Collaboration Guidelines
- **Subagent limits**: Concurrent subagents must not exceed 2; nested subagent calls are strictly prohibited.
- **Progress reporting**: Report ongoing operations and milestone summaries clearly and in real-time during the working process.

## Git Commit Guidelines
- **Automatic commit**: Automatically execute Git commits after completing feature development or modifications.
- **Commit language and format**: Commit messages must be in **English** and strictly follow Conventional Commits conventions (e.g., `feat(scope): ...`, `docs(guide): ...`).
- **Remove AI traces**: Strictly prohibit any `Co-Authored-By`, `anthropic`, `Claude`, `AI`, or similar signatures and identifiers.

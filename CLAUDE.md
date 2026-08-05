# faire-cuan

Standalone Python package that verifies, mirrors, and processes externally-signed OCI artifacts. Extracted from inline bash in the `oci-verify-import` Tekton task. Name follows Lightwell's Irish mythology convention ("faire-cuan" = harbor watch).

## Project structure

```
src/faire_cuan/
  cli.py              # Entry point, argparse with subcommands
  commands/            # Subcommand modules (verify, mirror, results) — each has register() + run()
  tools/               # Thin subprocess wrappers (cosign, oras, skopeo, openssl)
  auth.py              # Docker auth + CA bundle setup
  tekton.py            # Tekton result writing
  retry.py             # Exponential backoff retry
  verify.py            # Verify business logic (stub)
  mirror.py            # Mirror business logic (stub)
  results.py           # Results/SBOM/SLSA business logic (stub)
tests/
  tools/               # Tests for subprocess wrappers
```

## Commands

```
pytest                    # run tests
ruff check src/ tests/    # lint
ruff format src/ tests/   # format
tox                       # full CI suite (pytest, ruff, bandit, pip-audit)
```

## Design decisions

- **No runtime dependencies.** Only stdlib. Dev deps: pytest, ruff.
- **CLI uses command pattern.** Each subcommand in `commands/` has `register(subparsers)` and `run(args)`. Follows the same pattern as import-orchestrator.
- **Tool wrappers return data, not policy.** `cosign.verify()` returns `CompletedProcess` — the caller decides pass/fail. Other wrappers raise `ToolError` on non-zero exit.
- **Logging, not print.** Use `logging.getLogger(__name__)` for diagnostic output. `tekton.write_result()` prints to stdout intentionally (tee behavior for Tekton).
- **Flat package for now.** No `engine/` subpackage yet. Revisit after Phase 3 when the full scope of business logic modules is clear.
- **Exception hierarchy.** `OciVerifyError` (base) > `ValidationError`, `VerificationError`, `ToolError`.

## Testing conventions

- **Behavioral tests, not implementation tests.** Test what a function returns, raises, or produces — not how it constructs commands, orders flags, or sets env vars.
- **Tool wrapper tests** verify: return types, error propagation (stderr in `ToolError` message), optional parameter effects, edge cases (empty output). They do not verify exact command strings or subprocess settings.

## Refactoring phases

1. ~~Package skeleton, tool wrappers, CLI, tests~~ (done)
2. Implement `verify.py` and `mirror.py` business logic
3. Implement `results.py` (SBOM extraction, SLSA parsing, build index attach)
4. Dockerfile
5. Update Tekton YAML to use faire-cuan
6. End-to-end validation

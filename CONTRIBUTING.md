# Contributing

## Scope

This repository is currently maintained as a security validation lab with portfolio and pre-product goals.

Good contributions include:

- new controls
- connector improvements
- stricter validation logic
- report quality improvements
- better tests and CI
- documentation and sample report improvements

## Local setup

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

## Quality checks

Run before opening a change:

```bash
ruff check .
black --check .
mypy
bandit -c pyproject.toml -r controlguard
coverage run -m unittest discover -s tests -v
coverage report
```

## Testing expectations

- add tests for new controls
- prefer isolated mocks for external APIs
- keep tests portable across Windows and Ubuntu when possible
- use deterministic sample data for documentation artifacts

## Documentation expectations

If you change the report structure or README-facing examples:

- update `docs/samples/`
- update `scripts/generate_sample_reports.py`
- update relevant docs in `README.md`, `docs/ARCHITECTURE.md`, or release notes

## Design principles

- missing evidence must never inflate compliance
- applicability must be explicit
- reports must remain useful both for humans and automation
- secrets must come from runtime environment, never the repository

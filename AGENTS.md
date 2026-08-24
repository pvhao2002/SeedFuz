# Repository Guidelines

## Project Structure & Module Organization

This repository implements the university-defined IoT mutational-fuzzing project. Keep Python application code in `src/`, separating packet parsing, state-machine logic, bit/byte mutation, smart seed selection, Boofuzz orchestration, device monitoring, persistence, and the web dashboard into focused modules. Mirror that structure in `tests/`. Store captured PCAP seeds in `datasets/`, reproducible campaign definitions in `experiments/`, and generated logs, metrics, CSV/PDF reports, and figures in `results/`. Use `docs/research/` for technical notes, `docs/reports/` for thesis material, `papers/` for references, and treat `docs/university/` as the authoritative project specification.

## Build, Test, and Development Commands

No dependency manifest or runnable package is committed yet. When adding the first implementation, include `requirements.txt` or `pyproject.toml` and keep these commands working:

- `python -m venv .venv && source .venv/bin/activate`: create an isolated Linux-friendly environment.
- `python -m pip install -r requirements.txt`: install pinned dependencies, including Boofuzz and dashboard/test packages.
- `python -m pytest`: run the complete automated test suite.
- `python -m pytest tests/test_mutation.py -q`: run one focused test module.

Document the final dashboard and campaign entry points in `README.md` as soon as they exist.

## Coding Style & Naming Conventions

Follow PEP 8 with four-space indentation, type hints for public APIs, and short docstrings for protocol or mutation behavior. Use `snake_case` for files, functions, and variables; `PascalCase` for classes; and `UPPER_SNAKE_CASE` for constants. Prefer small, deterministic functions around packet parsing and mutation. Keep device addresses, timeouts, and campaign limits in configuration—not source code.

## Testing Guidelines

Use `pytest`; name files `test_<feature>.py` and tests `test_<behavior>()`. Add unit tests for header/payload extraction, state transitions, bit flipping, byte mutation, and sensitive-field selection. Use synthetic fixtures by default. Hardware tests must be explicitly marked and must never run in the default suite. Record fuzzing speed, crashes, crash timestamps, and memory-leak indicators for reproducible comparisons.

## Commit & Pull Request Guidelines

Git history is unavailable in this workspace, so use concise imperative commits such as `Add state-aware byte mutator`. Pull requests should describe scope, university requirement coverage, validation commands, and dataset/device assumptions. Include dashboard screenshots for UI changes and before/after metrics for algorithm changes.

## Security & Data Handling

Run campaigns only against owned or explicitly authorized IoT devices on an isolated network. Never commit credentials, public target addresses, sensitive packet captures, or large generated results. Preserve raw seed PCAPs; write mutations and outputs to separate paths.

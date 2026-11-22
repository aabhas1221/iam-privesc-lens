# Contributing

Thanks for your interest! Issues and pull requests are welcome.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Adding a technique

1. Add a `Technique` entry to `src/iam_privesc_lens/techniques.py` with a unique id, required
   actions (`all_of` / `any_of`), target kind, explanation, exploitation steps, remediation and at
   least one reference.
2. Add a minimal triggering policy to `CASES` in `tests/test_techniques.py`. The suite checks that every
   technique is detected and that removing any required action makes it disappear.
3. If the technique produces a multi-hop edge, add a scenario to `tests/fixtures/` and `tests/test_paths.py`.

## Guidelines

- Keep the analyzer offline: no network calls outside `fetch.py`.
- Use only synthetic data in examples and fixtures. Never include real account ids, ARNs or exports.
- Prefer false "conditional" over false "confirmed". If something cannot be decided statically, say so.

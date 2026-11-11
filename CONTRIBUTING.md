# Contributing

**kubeguard** — Kubernetes manifest audit with cross-resource analysis — is small on purpose: hand-written parsers, deterministic rules, no dependencies. Contributions that keep it that way are welcome.

## Setup

```bash
git clone https://github.com/xuange-hu/kubeguard
cd kubeguard
pip install -e ".[mcp]" pytest ruff
pytest                 # 201 tests
ruff check src tests
```

No `pip install` is needed to run the tests after a clone — the root
`conftest.py` puts `src/` on `sys.path`.

## Rules and where they live

`src/kubeguard/rules.py` (KG001…, 37 rules) with the third pass in `src/kubeguard/analyze.py`.

## Adding a rule

1. **The entry** in `src/kubeguard/rules.py` with `why` and `fix`.
2. **The check** in the pass it belongs to: single-resource, RBAC, or the third cross-resource pass.
3. **A trigger sample and a negative case** in `tests/`.
4. **A line in the demo manifest** so CI keeps asserting all 37 rules fire.

Then update the rule table and the test-count badge in `README.md`. CI warns
when the badge and pytest disagree.

## Rules of the road

- **Zero dependencies in `src/` outside `mcp_server.py`.** `tests/test_packaging.py`
  fails on an optional import leaking into a required path.
- **No network access.** Not in the scanner, not in the tests. Tests that need
  a file write it to `tmp_path`.
- **Every finding carries a location and its source text.** A report that says
  "something is wrong" without saying where gets closed and forgotten.
- **`absent` and `empty` are different.** Decide what the explicit empty form
  means before adding a rule that fires on a missing field.
- **Line numbers come from the parser.** Do not compute them in the rule.

## Commit and PR

- One logical change per commit.
- CI runs on 3.10–3.13 across Ubuntu and Windows. A test that passes only on
  your machine will be caught there, so run `pytest` before pushing.

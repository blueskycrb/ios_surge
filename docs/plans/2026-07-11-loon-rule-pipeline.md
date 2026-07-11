# Loon Rule Pipeline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Generate only AI, proxy, and China Loon rule sets with deterministic deduplication and `AI > Proxy > China` precedence.

**Architecture:** Move the Python merger out of GitHub Actions into an importable script. Normalize and deduplicate each source category, remove lower-priority rules fully covered by higher-priority rules, validate output size, and atomically update generated files only when their rules change.

**Tech Stack:** Python standard library, `unittest`, GitHub Actions, Loon rule syntax.

---

### Task 1: Extract the merger

**Files:**
- Create: `scripts/merge_rules.py`
- Test: `tests/test_merge_rules.py`

1. Add tests for normalization, `no-resolve` preference, domain coverage, CIDR coverage, and category precedence.
2. Run `python -m unittest discover -s tests -v` and confirm the tests fail before the module exists.
3. Implement downloading, parsing, deduplication, category precedence, validation, and atomic writes.
4. Run the tests and confirm they pass.

### Task 2: Simplify automation

**Files:**
- Modify: `.github/workflows/merge-rules.yml`
- Delete: `mihomo.list`

1. Replace the embedded script with test and generation commands.
2. Remove third-party Python dependency installation.
3. Check and commit only `china.list`, `proxy.list`, and `ai.list`.

### Task 3: Document and verify

**Files:**
- Modify: `README.md`

1. Document the three generated outputs and required Loon order.
2. Run the test suite.
3. Run `python scripts/merge_rules.py` against live sources.
4. Confirm there are no rules in Proxy covered by AI and no rules in China covered by AI or Proxy.
5. Review `git diff --check` and the final diff.

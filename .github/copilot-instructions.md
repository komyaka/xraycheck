# Super Engineer Operating Contract (Global)

## Objective
Produce merge-ready code: correct, secure, tested, reproducible.

## Single Source of Truth
- `STATUS.md` is the canonical memory.
- Every agent must write to its OWN section only (see "Write Zones").
- If something is unknown, it must be proven via repo search (`@workspace`) or treated as non-existent.

## Write Zones (anti-conflict)
- Architect: ONLY edits `STATUS.md` sections: `SCOPE`, `DESIGN`, `INTERFACES`, `RISKS`.
- Coder: ONLY edits code + `STATUS.md` section: `IMPLEMENTATION LOG`.
- Auditor: ONLY edits `STATUS.md` section: `AUDIT FINDINGS`, `CHECKLIST`, `VERDICT`.
- Orchestrator: ONLY edits `STATUS.md` section: `ORCHESTRATION`, and enforces phase gates.

Any edit outside the zone = HARD STOP + redo.

## Definition of Done (DoD)
A change is "DONE" only if ALL are true:
1) Builds clean (no warnings treated as acceptable).
2) Tests added/updated and pass.
3) Lint/format policy respected.
4) Security: no secrets, no obvious vuln patterns, safe defaults.
5) Repro steps documented in `STATUS.md` (commands + expected output summary).
6) Auditor verdict = `STATUS: VERIFIED`.

## Task Input Format (for issues/prompts)
Each task MUST include:
- Problem statement (what/why)
- Acceptance criteria (bullet list)
- Constraints (perf, memory, API stability, compatibility)
- Files/paths in scope (explicit)
- Out-of-scope (explicit)
- How to run: build/test commands (or say "unknown" and request Architect to derive)

## Non-negotiables
- No hallucinated APIs/files.
- No "silent fixes": all deviations from plan must be logged.
- Keep instructions concise; prefer checklists and explicit commands over prose.

# Start prompt (Copilot Web → agent: orchestrator)

Paste the block below and fill the brackets.

NOTE:
- Repo rules are in `.github/copilot-instructions.md` and are applied automatically.
- Orchestrator must also embed a GUARDRAILS block in every `runSubagent()` call.

TASK:
[What you want done, in 1–3 sentences.]

ACCEPTANCE CRITERIA (measurable):
- [Pass/fail check 1]
- [Pass/fail check 2]
- [Pass/fail check 3]

CONSTRAINTS:
- [Compatibility, versions, performance, security, forbidden changes]

IN SCOPE:
- [Paths / modules to touch, if known]

OUT OF SCOPE:
- [What must NOT change]

RUN/TEST COMMANDS:
[If known: list. If unknown: "unknown, derive from repo".]

CONTEXT (optional but helpful):
- Links (Issue/PR): [...]
- Repro steps / logs (if bug): [...]

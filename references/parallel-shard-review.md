# Deprecated — do not use (v4.44+)

Parallel shard workers and Task subagents are **removed** from ai-security-reviewer.

- **One agent** reads every config batch and HTTP module (`large-repo-runner.md`).
- `inventory.json` may still list `read_ranges` for huge files — those are **your** read plan, not worker assignments.
- Ignore `parallel.parallel_recommended` in inventory output.

See `SKILL.md`.

# Verification for 0.5.0

Locally tested on Linux with Node 22 and npm 10.

- Strict TypeScript and all 90 automated tests passed.
- Tests cover detector patterns, policy, baselines, staged Git blobs, hooks, safe outputs and terminal formatting.
- Fresh offline local installation tested both command aliases and doctor.
- Terminal image rendered from a real pseudo-terminal capture with synthetic fixture data.
- npm audit reported zero known dependency vulnerabilities at build time, not a code audit.
- Node 20/22 on Linux, Windows and macOS are configured in Actions. Check the actual Actions results before inferring cross-platform success.
- No npm registry publication. Compiled CLI and full source are included on GitHub.

Reports can contain sensitive paths and hashes. Keep them private. Read README.md for limits.

# Changelog

## 0.5.0

- Renamed to CloakSift for the first public GitHub release.
- Updated commands, config, hook markers, report identity and terminal banner.
- Reworked quick start, Arabic instructions and contributor docs.
- Fixed the CI package-install filename; CI has read-only contents permissions.


## 0.4.0

- Color-coded human-readable reports with explicit labels and exit status.
- ASCII banner and grouped workspace menu, with compact narrow-terminal banner.
- Return to the menu after actions; invalid choices can be retried.
- Staged Git review and doctor shortcuts; pasted scans now honor current policy.
- Honor NO_COLOR (including empty), TERM=dumb and non-TTY output.
- No ANSI in JSON, SARIF, saved reports or redacted stdout.
- Escape terminal controls in displayed errors and finding metadata.
- README terminal image, contribution templates and release checklist.
- 17 UI regressions, plus actual terminal checks.

Detection rules are unchanged. No accuracy increase is claimed. Baselines must be reviewed and recreated for engine 0.5.0.

## 0.3.0

CLI-only offline package, command aliases, recursive scans, strict policies,
reviewed baselines, JSON/SARIF, safer file outputs, extra credential patterns,
and local hook management.

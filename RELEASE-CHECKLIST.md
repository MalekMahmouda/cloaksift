# Release checklist

- Run `npm ci --ignore-scripts` and `npm run check`.
- Review license, security policy, synthetic fixtures and terminal image for sensitive data.
- Keep compiled `dist` in sync with source and bump the engine version deliberately.
- Check offline installation and both aliases from a fresh prefix.
- Inspect the Actions matrix before claiming cross-platform support.
- Review release notes and keep detector limits visible.
- Do not publish to npm without an explicit maintainer decision. The package is private.

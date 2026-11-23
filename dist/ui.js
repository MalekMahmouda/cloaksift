const codes = { cyan: 36, green: 32, yellow: 33, red: 31, dim: 2, bold: 1 };
export function useColor(tty = Boolean(process.stdout.isTTY), env = process.env) {
    return tty && !("NO_COLOR" in env) && env.TERM !== "dumb";
}
export function paint(text, tone, enabled = useColor()) {
    return enabled ? `\x1b[${codes[tone]}m${text}\x1b[0m` : text;
}
export function safeDisplay(text) {
    return text.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
export function banner(version, width = process.stdout.columns || 80) {
    const art = width >= 68 ? [
        "   +--------------------------------------------------+",
        "   |  C L O A K S I F T                     [ LOCAL ] |",
        "   |  Review before you share.                        |",
        "   +--------------------------------------------------+"
    ].join("\n") : "  [ CS ]  CLOAKSIFT";
    return `${paint(art, "cyan")}\n\n  ${paint("OFFLINE REVIEW WORKSPACE", "bold")}  ${paint(`v${version}`, "dim")}\n  Secrets / personal data / instruction signals\n  ${paint("No network. No telemetry. No runtime dependencies.", "dim")}`;
}
export function menu(version) {
    return `${banner(version)}\n\n  ${paint("SCAN", "cyan")}\n    ${paint("1", "bold")}  File or folder       Recursive local review\n    ${paint("2", "bold")}  Paste text           Multiline scratch scan\n    ${paint("3", "bold")}  Staged Git changes   Review index, not worktree\n\n  ${paint("TOOLS", "cyan")}\n    ${paint("4", "bold")}  Doctor               Check runtime and policy\n    ${paint("5", "bold")}  Command guide        Reports, redaction and hooks\n    ${paint("0", "dim")}  Exit\n\n  ${paint("Heuristic checks. A clean scan is not proof of safety.", "yellow")}\n`;
}
export function renderReport(r, color = useColor()) {
    const tone = r.riskScore >= 35 ? "red" : r.riskScore ? "yellow" : "green";
    const lines = ["", `  ${paint(safeDisplay(JSON.stringify(r.file)), "bold", color)}  ${paint(`risk ${r.riskScore}/100`, tone, color)}`];
    for (const f of r.findings) {
        const label = f.suppressed ? "BASELINED" : f.severity.toUpperCase();
        const level = f.suppressed ? "dim" : ["critical", "high"].includes(f.severity) ? "red" : "yellow";
        lines.push(`  ${paint(label.padEnd(10), level, color)} ${safeDisplay(f.rule)}  ${f.line}:${f.column}`);
        lines.push(`             ${safeDisplay(f.message)}`);
    }
    if (!r.findings.length)
        lines.push(`  ${paint("No findings. This is not proof of safety.", "green", color)}`);
    return lines;
}
export function outcome(status, color = useColor()) {
    const label = status === 2 ? "INCOMPLETE / ERROR" : status === 1 ? "REVIEW REQUIRED" : "NO POLICY BLOCK";
    return paint(`${label}  /  exit ${status}`, status === 2 ? "yellow" : status === 1 ? "red" : "green", color);
}
//# sourceMappingURL=ui.js.map
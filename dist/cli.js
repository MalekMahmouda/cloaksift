#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createInterface } from "node:readline/promises";
import { scanText, redactText, listRules } from "./scanner.js";
import { collect, git, readText, saveNew, stdin } from "./io.js";
import { baseline, fingerprint, policy, uniqueOutputs } from "./policy.js";
import { menu, paint, renderReport, outcome, safeDisplay, useColor } from "./ui.js";
const VERSION = "0.5.0";
function parse(args) {
    const o = { paths: [], staged: false, format: "text", excludes: [] };
    const value = (i) => { const v = args[i]; if (!v || v.startsWith("--"))
        throw new Error("Option requires a value."); return v; };
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === "--") {
            o.paths.push(...args.slice(i + 1));
            break;
        }
        if (a === "--staged")
            o.staged = true;
        else if (a === "--json")
            o.format = "json";
        else if (a === "--format") {
            const v = value(++i);
            if (!["text", "json", "sarif"].includes(v))
                throw new Error("Format must be text, json or sarif.");
            o.format = v;
        }
        else if (a === "--exclude")
            o.excludes.push(value(++i));
        else if (a === "--config")
            o.config = value(++i);
        else if (a === "--baseline")
            o.baseline = value(++i);
        else if (a === "--output" || a === "-o")
            o.output = value(++i);
        else if (a === "--fail-on-risk") {
            const v = value(++i);
            if (!/^\d{1,3}$/.test(v) || +v > 100)
                throw new Error("--fail-on-risk expects an integer from 0 to 100.");
            o.threshold = +v;
        }
        else if (a === "--block") {
            const v = value(++i).split(",");
            if (v.some(x => !["secret", "pii", "injection"].includes(x)))
                throw new Error("--block expects secret,pii,injection categories.");
            o.block = v;
        }
        else if (a.startsWith("-") && a !== "-")
            throw new Error(`Unknown option: ${JSON.stringify(a)}`);
        else
            o.paths.push(a);
    }
    if (o.staged && o.paths.length)
        throw new Error("Do not combine --staged with paths.");
    if (o.paths.filter(p => p === "-").length > 1)
        throw new Error("Read stdin only once.");
    return o;
}
function report(file, text, p, approved) {
    const raw = scanText(text);
    const contentHash = createHash("sha256").update(text).digest("hex");
    const lineStarts = [0];
    for (let i = 0; i < text.length; i++)
        if (text[i] === "\n")
            lineStarts.push(i + 1);
    const findings = raw.findings.filter(f => !p.disabledRules.includes(f.rule)).map(f => {
        const fp = fingerprint(file, contentHash, f);
        let lo = 0, hi = lineStarts.length;
        while (lo + 1 < hi) {
            const mid = (lo + hi) >>> 1;
            if (lineStarts[mid] <= f.start)
                lo = mid;
            else
                hi = mid;
        }
        return { ...f, line: lo + 1, column: f.start - lineStarts[lo] + 1, fingerprint: fp, suppressed: approved.has(fp) };
    });
    const active = findings.filter(f => !f.suppressed);
    const counts = { secret: 0, pii: 0, injection: 0 };
    const weights = { low: 10, medium: 20, high: 35, critical: 45 };
    for (const f of active)
        counts[f.category]++;
    return { file, counts, riskScore: Math.min(100, active.reduce((s, f) => s + weights[f.severity], 0)), findings };
}
function sarif(reports, omissions) {
    return { version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{
                tool: { driver: { name: "CloakSift", version: VERSION, rules: listRules().map(r => ({ id: r.id, shortDescription: { text: r.message } })) } },
                invocations: [{ executionSuccessful: omissions.length === 0, toolExecutionNotifications: omissions.map(x => ({ level: "error", message: { text: `${JSON.stringify(x.file)}: ${x.reason}` } })) }],
                results: reports.flatMap(r => r.findings.map(f => ({ ruleId: f.rule, level: f.severity === "low" ? "note" : f.severity === "medium" ? "warning" : "error", message: { text: f.message },
                    partialFingerprints: { "cloaksift/v1": f.fingerprint },
                    ...(f.suppressed ? { suppressions: [{ kind: "external", justification: "Explicit reviewed baseline" }] } : {}),
                    locations: [{ physicalLocation: { artifactLocation: { uri: r.file.split(/[\\/]/).map(encodeURIComponent).join("/") }, region: { startLine: f.line, startColumn: f.column } } }]
                })))
            }] };
}
export async function main(argv = process.argv.slice(2)) {
    try {
        const [command, ...args] = argv;
        if (!command) {
            if (process.stdin.isTTY && process.stdout.isTTY)
                return interactive();
            help();
            return 0;
        }
        if (["--help", "-h", "help"].includes(command)) {
            help();
            return 0;
        }
        if (["--version", "-v"].includes(command)) {
            console.log(VERSION);
            return 0;
        }
        if (command === "rules") {
            if (args.length)
                throw new Error("rules takes no arguments.");
            console.log(JSON.stringify(listRules(), null, 2));
            return 0;
        }
        if (command === "doctor") {
            if (args.length)
                throw new Error("doctor takes no arguments.");
            console.log(`CloakSift ${VERSION}\nNode ${process.version}\nRuntime dependencies: none\nScanner network calls: none`);
            try {
                git(["--version"]);
                console.log("Git: available");
            }
            catch {
                console.log("Git: unavailable (only Git features affected)");
            }
            policy();
            console.log("Policy: valid\nLimits: 1 MB/file, 20 MB/batch, 2000 entries. No finding is not proof of safety.");
            return 0;
        }
        if (command === "config") {
            if (args.length !== 1 || args[0] !== "init")
                throw new Error("Usage: cloaksift config init");
            saveNew(".cloaksift.json", JSON.stringify({ version: 1, block: ["secret"], exclude: [], disabledRules: [] }, null, 2) + "\n");
            console.log("Created .cloaksift.json. Review exclusions and blocking policy before use.");
            return 0;
        }
        if (command === "init" || command === "hook") {
            if (command === "init" && args.length)
                throw new Error("init takes no arguments.");
            if (command === "hook" && (args.length !== 1 || !["install", "uninstall", "status"].includes(args[0])))
                throw new Error("Usage: cloaksift hook install|uninstall|status");
            return hook(command === "init" ? "install" : args[0]);
        }
        if (command === "redact" || command === "prepare") {
            const o = parse(args);
            if (o.paths.length !== 1 || o.staged || o.baseline || o.config || o.excludes.length || o.block || o.threshold !== undefined || o.format !== "text")
                throw new Error(`Usage: cloaksift ${command} <file|-> [-o NEW_FILE]`);
            if (o.output)
                uniqueOutputs([o.output], o.paths);
            const text = o.paths[0] === "-" ? stdin() : readText(o.paths[0]);
            const raw = scanText(text);
            if (command === "prepare" && raw.counts.injection) {
                console.error("Export refused: instruction-manipulation signals need human review. No text was written.");
                return 1;
            }
            const out = redactText(text, raw);
            if (o.output) {
                saveNew(o.output, out);
                console.error("Created new redacted file. Source unchanged. Review it before sharing.");
            }
            else
                process.stdout.write(out);
            return 0;
        }
        const isBaseline = command === "baseline";
        if (command !== "scan" && !isBaseline)
            throw new Error(`Unknown command: ${JSON.stringify(command)}`);
        if (isBaseline && args[0] !== "create")
            throw new Error("Usage: cloaksift baseline create <paths...> -o NEW_FILE");
        const o = parse(isBaseline ? args.slice(1) : args);
        if (isBaseline && (!o.output || o.baseline || !o.paths.length && !o.staged))
            throw new Error("Baseline creation requires explicit paths or --staged and -o NEW_FILE; no --baseline.");
        const p = policy(o.config);
        if (o.threshold !== undefined)
            p.failOnRisk = o.threshold;
        if (o.block)
            p.block = o.block;
        const approved = baseline(o.baseline);
        const inputs = collect(o.paths, o.staged, [...p.exclude, ...o.excludes]);
        const reports = inputs.targets.map(t => report(t.file, t.text, p, approved));
        if (o.output)
            uniqueOutputs([o.output], [...o.paths, ...inputs.targets.map(t => t.file), ...(o.config ? [o.config] : []), ...(o.baseline ? [o.baseline] : [])]);
        if (isBaseline) {
            if (inputs.skipped.length)
                throw new Error("Baseline refused: incomplete input. Scan first and resolve omissions.");
            const fingerprints = reports.flatMap(r => r.findings.map(f => f.fingerprint));
            saveNew(o.output, JSON.stringify({ version: 1, engine: VERSION, fingerprints }, null, 2) + "\n");
            console.log(`Created baseline with ${fingerprints.length} findings. Using it explicitly suppresses these exact file-content findings. Review carefully; changed files are scanned again.`);
            return 0;
        }
        const summary = { filesScanned: reports.length, findings: reports.reduce((n, r) => n + r.findings.filter(f => !f.suppressed).length, 0), suppressed: reports.reduce((n, r) => n + r.findings.filter(f => f.suppressed).length, 0) };
        const status = inputs.skipped.length ? 2 : reports.some(r => r.findings.some(f => !f.suppressed && p.block.includes(f.category)) || p.failOnRisk !== undefined && r.riskScore >= p.failOnRisk) ? 1 : 0;
        let output;
        if (o.format === "json")
            output = JSON.stringify({ version: VERSION, ...summary, exitCode: status, policy: p, skipped: inputs.skipped, excluded: inputs.excluded, reports }, null, 2);
        else if (o.format === "sarif")
            output = JSON.stringify(sarif(reports, inputs.skipped), null, 2);
        else {
            const color = !o.output && useColor();
            const lines = [paint(`CloakSift ${VERSION} | offline review, not a security guarantee`, "cyan", color)];
            for (const r of reports)
                lines.push(...renderReport(r, color));
            for (const x of inputs.skipped)
                lines.push(`Skipped ${JSON.stringify(x.file)}: ${x.reason}`);
            for (const x of inputs.excluded)
                lines.push(`Excluded ${JSON.stringify(x.file)}: ${x.reason}`);
            lines.push(`${summary.filesScanned} file(s) scanned; ${summary.findings} active findings; ${summary.suppressed} baselined; ${inputs.skipped.length} skipped; ${inputs.excluded.length} excluded.`);
            if (p.disabledRules.length)
                lines.push(`Disabled rules: ${p.disabledRules.join(", ")}`);
            lines.push(`Blocking categories: ${p.block.join(", ") || "none"}. Exit ${status}.`);
            lines.push(outcome(status, color));
            output = lines.join("\n");
        }
        if (o.output) {
            saveNew(o.output, output + "\n");
            console.error(`Report saved. Exit ${status}.`);
        }
        else
            console.log(output);
        return status;
    }
    catch (e) {
        console.error(safeDisplay(e instanceof Error ? e.message : "Operation failed."));
        return 2;
    }
}
function hook(action) {
    const path = resolve(git(["rev-parse", "--git-path", "hooks/pre-commit"]).toString("utf8").trim());
    const marker = "# CloakSift managed hook v1";
    const quote = (s) => "'" + s.replace(/'/g, "'\\''") + "'";
    const body = `#!/bin/sh\n${marker}\n# Reinstall if Node or the installed package moves.\nexec ${quote(process.execPath)} ${quote(fileURLToPath(import.meta.url))} scan --staged\n`;
    if (action === "status") {
        console.log(existsSync(path) ? "A pre-commit hook exists. Inspect before changing it." : "No pre-commit hook installed.");
        return 0;
    }
    if (action === "uninstall") {
        if (!existsSync(path)) {
            console.log("No hook to remove.");
            return 0;
        }
        if (readFileSync(path, "utf8") !== body)
            throw new Error("Hook differs from this installation's managed hook. Left untouched; inspect manually.");
        unlinkSync(path);
        console.log("Removed this installation's managed hook.");
        return 0;
    }
    if (existsSync(path))
        throw new Error("Existing pre-commit hook left untouched. Integrate scan --staged manually.");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, body, { flag: "wx", mode: 0o755 });
    console.log(`Installed local hook at ${JSON.stringify(path)}. Existing hooks are never replaced.`);
    return 0;
}
async function interactive() {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true, historySize: 0 });
    const iterator = rl[Symbol.asyncIterator]();
    const ask = async (prompt) => { process.stdout.write(prompt); const item = await iterator.next(); return item.done ? undefined : item.value; };
    let lastStatus = 0;
    try {
        for (;;) {
            console.log(menu(VERSION));
            const response = await ask(paint("  Choose [0-5] > ", "cyan"));
            if (response === undefined)
                return lastStatus;
            const action = response.trim();
            if (action === "0" || !action)
                return lastStatus;
            if (!["1", "2", "3", "4", "5"].includes(action)) {
                console.log(paint("  Choose a number from 0 to 5.", "yellow"));
                continue;
            }
            if (action === "5")
                help();
            else if (action === "4")
                lastStatus = await main(["doctor"]);
            else if (action === "3")
                lastStatus = await main(["scan", "--staged"]);
            else if (action === "1") {
                const path = await ask("  File/folder path (no shell quotes; blank cancels) > ");
                if (path === undefined)
                    return lastStatus;
                if (!path.trim())
                    continue;
                lastStatus = await main(["scan", "--", path]);
            }
            else {
                console.log(paint("  Paste text, then type .scan on its own line.", "cyan"));
                console.log("  Input is visible in terminal scrollback. Use a file for real secrets.");
                const lines = [];
                let size = 0;
                for (;;) {
                    const line = await ask("  > ");
                    if (line === undefined)
                        return lastStatus;
                    if (line === ".scan")
                        break;
                    size += Buffer.byteLength(line) + 1;
                    if (size > 1_000_000)
                        throw new Error("Input exceeds 1 MB.");
                    lines.push(line);
                }
                const p = policy();
                const r = report("<interactive>", lines.join("\n"), p, new Set());
                lastStatus = r.findings.some(f => p.block.includes(f.category)) || p.failOnRisk !== undefined && r.riskScore >= p.failOnRisk ? 1 : 0;
                console.log(renderReport(r).join("\n"));
                console.log(`\n  ${outcome(lastStatus)}\n  Text was not saved or sent.`);
            }
            console.log("");
            if (await ask(paint("  Enter to return to workspace > ", "dim")) === undefined)
                return lastStatus;
        }
    }
    finally {
        rl.close();
    }
}
function help() {
    console.log(`CloakSift ${VERSION} | offline secret/PII review CLI

  cloaksift                              Interactive workspace (TTY)
  cloaksift scan <files/folders...>        Recursive UTF-8 scan
  cloaksift scan --staged                  Scan actual staged Git blobs
  cloaksift scan -                         Read piped text
  cloaksift scan . --format json|sarif -o NEW_REPORT
  cloaksift scan . --exclude '**/*.svg' --block secret,pii,injection
  cloaksift scan . --config policy.json --baseline reviewed.json
  cloaksift baseline create <paths...> -o NEW_BASELINE
  cloaksift redact <file|-> [-o NEW_FILE]   Redact secrets/PII for review
  cloaksift prepare <file|-> [-o NEW_FILE]  Refuse output on injection signals
  cloaksift config init                    Create policy, never overwrite
  cloaksift hook install|uninstall|status   Current repository only
  cloaksift doctor                         Check runtime and policy
  cloaksift rules                          List heuristic rules
  cloaksift --version

Alias: cloak-sift. Install from cloned folder: npm install -g . --offline --ignore-scripts --no-audit --no-fund
Fallback without install: node dist/cli.js <command>
No network calls, telemetry, LLM or runtime dependencies.
Exit 0: no policy block; 1: blocking finding/review; 2: invalid/incomplete.
Default blocks secrets only. PII/injection are informational unless configured.
Default folder exclusions: .git, node_modules, .venv, vendor, coverage.
Skipped content is incomplete (exit 2); explicit exclusions are listed.
Limits: 1 MB/file, 20 MB/batch, 2000 entries. Symlinks refused.
Use -- before dash-prefixed paths. Outputs never overwrite existing files.
A clean scan is not proof of safety. Redaction is best-effort, review output.
Injection rules are English heuristics, not an AI firewall.
Color is automatic in terminals; NO_COLOR (even empty) or TERM=dumb disables it.
Pipes, report files, JSON/SARIF and redacted stdout remain unstyled.`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(resolve(process.argv[1]))).href)
    main().then(code => { process.exitCode = code; }).catch(() => { console.error("Operation failed."); process.exitCode = 2; });
//# sourceMappingURL=cli.js.map
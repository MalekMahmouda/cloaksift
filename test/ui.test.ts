import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { useColor, paint, banner, renderReport, safeDisplay, outcome } from "../src/ui.js";
const cli = resolve("dist/cli.js");
describe("terminal presentation", () => {
  it("colors only a suitable TTY", () => { expect(useColor(true, { TERM: "xterm" })).toBe(true); expect(useColor(false, { FORCE_COLOR: "1" })).toBe(false); });
  it.each(["", "1", "false"])("honors NO_COLOR=%j even when FORCE_COLOR is set", value => { expect(useColor(true, { NO_COLOR: value, FORCE_COLOR: "1" })).toBe(false); });
  it("honors a dumb terminal", () => { expect(useColor(true, { TERM: "dumb" })).toBe(false); });
  it("keeps plain text unchanged", () => { expect(paint("hello", "cyan", false)).toBe("hello"); });
  it("uses balanced ANSI styling", () => { expect(paint("hello", "cyan", true)).toBe("\x1b[36mhello\x1b[0m"); });
  it("has a compact narrow-terminal banner", () => { expect(banner("0.5.0", 40)).toContain("[ CS ]"); });
  it("shows a full ASCII banner on wide terminals", () => { expect(banner("0.5.0", 80)).toContain("C L O A K S I F T"); });
  it("escapes terminal controls and bidi overrides", () => { expect(safeDisplay("x\x1b[31m\u202ey")).toBe("x\\u001b[31m\\u202ey"); });
  it("uses explicit statuses rather than relying on color", () => { expect(outcome(0,false)).toContain("NO POLICY BLOCK"); expect(outcome(1,false)).toContain("REVIEW REQUIRED"); expect(outcome(2,false)).toContain("INCOMPLETE"); });
  it("preserves severity, location and baseline in readable output", () => {
    const text = renderReport({ file: "a", riskScore: 0, findings: [{ severity:"high", rule:"example", line:2, column:5, message:"Review", suppressed:true }] },false).join("\n");
    expect(text).toContain("BASELINED"); expect(text).toContain("2:5"); expect(text).not.toContain("\x1b");
  });
  it("does not decorate piped output even with FORCE_COLOR", () => {
    const r = spawnSync(process.execPath,[cli,"scan","-"],{input:"password=synthetic-credential",encoding:"utf8",env:{...process.env,FORCE_COLOR:"1"}});
    expect(r.status).toBe(1); expect(r.stdout).not.toContain("\x1b"); expect(r.stdout).not.toContain("synthetic-credential");
  });
  it.each(["json","sarif"])("keeps %s machine-readable", format => {
    const r=spawnSync(process.execPath,[cli,"scan","-","--format",format],{input:"hello",encoding:"utf8",env:{...process.env,FORCE_COLOR:"1"}});
    expect(r.status).toBe(0); expect(()=>JSON.parse(r.stdout)).not.toThrow(); expect(r.stdout).not.toContain("\x1b");
  });
  it("writes unstyled text reports", () => {
    const d=mkdtempSync(join(tmpdir(),"pg-ui-"));
    try { const out=join(d,"report.txt"); const r=spawnSync(process.execPath,[cli,"scan","-","-o",out],{input:"hello",encoding:"utf8",env:{...process.env,FORCE_COLOR:"1"}}); expect(r.status).toBe(0); expect(readFileSync(out,"utf8")).not.toContain("\x1b"); } finally {rmSync(d,{recursive:true,force:true});}
  });
  it("leaves redacted stdout as data, without UI decoration", () => {
    const r=spawnSync(process.execPath,[cli,"redact","-"],{input:"hello",encoding:"utf8",env:{...process.env,FORCE_COLOR:"1"}});
    expect(r.stdout).toBe("hello");
  });
});

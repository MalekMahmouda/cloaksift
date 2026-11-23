import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { listRules, type ScanFinding, type FindingCategory } from "./scanner.js";
import { readText } from "./io.js";
export interface Policy { exclude: string[]; disabledRules: string[]; block: FindingCategory[]; failOnRisk?: number }
export const defaults: Policy = { exclude: [], disabledRules: [], block: ["secret"] };
function object(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function strings(value: unknown): value is string[] { return Array.isArray(value) && value.every(x => typeof x === "string"); }
export function policy(path?: string): Policy {
  const selected = path ?? (existsSync(".cloaksift.json") ? ".cloaksift.json" : undefined);
  if (!selected) return { ...defaults };
  let raw: unknown;
  try { raw = JSON.parse(readText(selected)); } catch { throw new Error("Cannot read valid JSON policy."); }
  if (!object(raw) || Object.keys(raw).some(k => !["version", "exclude", "disabledRules", "block", "failOnRisk"].includes(k)) || raw.version !== 1) throw new Error("Invalid policy: version must be 1; unknown keys are refused.");
  const p: Policy = { ...defaults };
  if (raw.exclude !== undefined) { if (!strings(raw.exclude)) throw new Error("exclude must be a string array."); p.exclude = raw.exclude; }
  if (raw.disabledRules !== undefined) {
    if (!strings(raw.disabledRules) || raw.disabledRules.some(id => !listRules().some(r => r.id === id))) throw new Error("Unknown or invalid disabledRules.");
    p.disabledRules = raw.disabledRules;
  }
  if (raw.block !== undefined) { if (!strings(raw.block) || raw.block.some(c => !["secret", "pii", "injection"].includes(c))) throw new Error("Invalid blocking categories."); p.block = raw.block as FindingCategory[]; }
  if (raw.failOnRisk !== undefined) { if (!Number.isInteger(raw.failOnRisk) || Number(raw.failOnRisk) < 0 || Number(raw.failOnRisk) > 100) throw new Error("Invalid failOnRisk."); p.failOnRisk = Number(raw.failOnRisk); }
  return p;
}
export function fingerprint(file: string, contentHash: string, f: ScanFinding): string {
  return createHash("sha256").update(JSON.stringify([file.replaceAll("\\", "/"), contentHash, f.rule, f.start, f.end])).digest("hex");
}
export function baseline(path?: string): Set<string> {
  if (!path) return new Set();
  let raw: unknown;
  try { raw = JSON.parse(readText(path)); } catch { throw new Error("Cannot read valid JSON baseline."); }
  if (!object(raw) || raw.version !== 1 || raw.engine !== "0.5.0" || !strings(raw.fingerprints) || raw.fingerprints.some(x => !/^[a-f0-9]{64}$/.test(x))) throw new Error("Invalid or incompatible baseline. Review and recreate it.");
  return new Set(raw.fingerprints);
}
export function uniqueOutputs(outputs: string[], inputs: string[]) {
  const paths = outputs.map(x => resolve(x));
  if (new Set(paths).size !== paths.length || inputs.some(x => paths.includes(resolve(x)))) throw new Error("Output paths must be distinct from inputs and each other.");
}

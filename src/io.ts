import { existsSync, lstatSync, readFileSync, readdirSync, readSync, writeFileSync } from "node:fs";
import { resolve, relative, sep } from "node:path";
import { execFileSync } from "node:child_process";

export const MAX_BYTES = 1_000_000;
export interface Target { file: string; text: string }
export interface Omission { file: string; reason: string }
export interface Inputs { targets: Target[]; skipped: Omission[]; excluded: Omission[] }
const DEFAULT_DIRS = new Set([".git", "node_modules", ".venv", "vendor", "coverage"]);
export function decode(buffer: Buffer): string {
  if (buffer.length > MAX_BYTES) throw new Error("Input exceeds the 1 MB limit.");
  if (buffer.includes(0)) throw new Error("Binary input is not supported.");
  try { return new TextDecoder("utf-8", { fatal: true }).decode(buffer); }
  catch { throw new Error("Input is not valid UTF-8."); }
}
export function readText(file: string): string {
  try {
    const stat = lstatSync(file);
    if (!stat.isFile() || stat.size > MAX_BYTES) throw new Error();
    return decode(readFileSync(file));
  } catch { throw new Error(`Cannot read ${JSON.stringify(file)}: expected a regular UTF-8 file of at most 1 MB; symlinks refused.`); }
}
export function stdin(): string {
  const chunks: Buffer[] = [], chunk = Buffer.alloc(65536);
  let total = 0;
  for (;;) {
    const n = readSync(0, chunk, 0, chunk.length, null);
    if (!n) break;
    total += n;
    if (total > MAX_BYTES) throw new Error("Input exceeds the 1 MB limit.");
    chunks.push(Buffer.from(chunk.subarray(0, n)));
  }
  return decode(Buffer.concat(chunks));
}
export function git(args: string[], maxBuffer = 8_000_000): Buffer {
  try { return execFileSync("git", args, { maxBuffer, stdio: ["ignore", "pipe", "pipe"] }); }
  catch { throw new Error("Git read failed. Check repository, Git availability and size limits."); }
}
export function glob(pattern: string): RegExp {
  if (!pattern || pattern.length > 300 || pattern.includes("\\") || pattern.includes("..")) throw new Error("Invalid exclude glob. Use relative forward-slash paths without '..'.");
  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "*" && pattern[i + 1] === "*") { i++; if (pattern[i + 1] === "/") { i++; out += "(?:.*/)?"; } else out += ".*"; }
    else if (c === "*") out += "[^/]*";
    else if (c === "?") out += "[^/]";
    else out += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(out + "$", "u");
}
export function collect(paths: string[], staged: boolean, excludes: string[] = []): Inputs {
  const result: Inputs = { targets: [], skipped: [], excluded: [] };
  const patterns = excludes.map(glob), seen = new Set<string>();
  let total = 0, visited = 0;
  const normalize = (file: string) => file.split(sep).join("/").replace(/^\.\//, "");
  const excluded = (file: string) => {
    const p = normalize(file);
    const yes = p.split("/").some(part => DEFAULT_DIRS.has(part)) || patterns.some(re => re.test(p));
    if (yes) result.excluded.push({ file, reason: "Default directory exclusion or explicit exclude glob." });
    return yes;
  };
  const add = (file: string, text: string) => {
    total += Buffer.byteLength(text);
    if (total > 20_000_000) throw new Error("Total decoded input exceeds 20 MB; scan smaller batches.");
    result.targets.push({ file, text });
  };
  const budget = () => { if (++visited > 2000) throw new Error("More than 2000 entries; scan smaller batches."); };
  if (staged) {
    const root = git(["rev-parse", "--show-toplevel"]).toString("utf8").trim();
    const indexGit = (args: string[], maxBuffer?: number) => git(["-C", root, ...args], maxBuffer);
    const names = indexGit(["diff", "--cached", "--name-only", "--diff-filter=ACMRTU", "-z"]).toString("utf8").split("\0").filter(Boolean);
    for (const file of names) {
      budget(); if (excluded(file)) continue;
      const entry = indexGit(["--literal-pathspecs", "ls-files", "--stage", "-z", "--", file]).toString("utf8");
      const match = /^(100644|100755) ([a-f0-9]+) 0\t/.exec(entry);
      if (!match) { result.skipped.push({ file, reason: "Non-regular or conflicted index entry." }); continue; }
      try { add(file, decode(indexGit(["cat-file", "blob", match[2]!], MAX_BYTES + 1))); }
      catch (e) { if (e instanceof Error && e.message.startsWith("Total decoded")) throw e; result.skipped.push({ file, reason: "Unreadable, binary, invalid UTF-8 or larger than 1 MB." }); }
    }
    return result;
  }
  if (!paths.length) {
    if (process.stdin.isTTY) throw new Error("Pass files, a folder, or pipe UTF-8 text.");
    add("<stdin>", stdin()); return result;
  }
  const walk = (path: string) => {
    const absolute = resolve(path), display = relative(process.cwd(), absolute) || ".";
    if (seen.has(absolute)) return;
    seen.add(absolute); budget();
    if (excluded(display)) return;
    let stat;
    try { stat = lstatSync(absolute); } catch { result.skipped.push({ file: display, reason: "Missing or unreadable path." }); return; }
    if (stat.isDirectory()) {
      let children: string[];
      try { children = readdirSync(absolute).sort(); } catch { result.skipped.push({ file: display, reason: "Unreadable folder." }); return; }
      for (const child of children) walk(resolve(absolute, child));
    } else {
      try { add(display, readText(absolute)); }
      catch (e) { if (e instanceof Error && e.message.startsWith("Total decoded")) throw e; result.skipped.push({ file: display, reason: "Not a readable regular UTF-8 file of at most 1 MB; symlinks refused." }); }
    }
  };
  for (const p of paths) { if (p === "-") add("<stdin>", stdin()); else walk(p); }
  return result;
}
export function saveNew(path: string, content: string): void {
  if (existsSync(path)) throw new Error("Output exists; choose a new path. No file was overwritten.");
  try { writeFileSync(path, content, { flag: "wx", mode: 0o600 }); }
  catch { throw new Error("Cannot create output file. Check path, permissions and available space."); }
}

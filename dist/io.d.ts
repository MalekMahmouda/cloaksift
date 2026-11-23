export declare const MAX_BYTES = 1000000;
export interface Target {
    file: string;
    text: string;
}
export interface Omission {
    file: string;
    reason: string;
}
export interface Inputs {
    targets: Target[];
    skipped: Omission[];
    excluded: Omission[];
}
export declare function decode(buffer: Buffer): string;
export declare function readText(file: string): string;
export declare function stdin(): string;
export declare function git(args: string[], maxBuffer?: number): Buffer;
export declare function glob(pattern: string): RegExp;
export declare function collect(paths: string[], staged: boolean, excludes?: string[]): Inputs;
export declare function saveNew(path: string, content: string): void;
//# sourceMappingURL=io.d.ts.map
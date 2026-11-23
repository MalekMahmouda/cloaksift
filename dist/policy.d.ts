import { type ScanFinding, type FindingCategory } from "./scanner.js";
export interface Policy {
    exclude: string[];
    disabledRules: string[];
    block: FindingCategory[];
    failOnRisk?: number;
}
export declare const defaults: Policy;
export declare function policy(path?: string): Policy;
export declare function fingerprint(file: string, contentHash: string, f: ScanFinding): string;
export declare function baseline(path?: string): Set<string>;
export declare function uniqueOutputs(outputs: string[], inputs: string[]): void;
//# sourceMappingURL=policy.d.ts.map
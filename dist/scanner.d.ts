export type FindingCategory = "secret" | "pii" | "injection";
export type FindingSeverity = "low" | "medium" | "high" | "critical";
/** Findings intentionally omit matched text so callers do not accidentally log a secret. */
export interface ScanFinding {
    rule: string;
    category: FindingCategory;
    severity: FindingSeverity;
    message: string;
    start: number;
    end: number;
    replacement: string;
}
export interface ScanResult {
    /** Capped rule-weighted triage score, not a probability or guarantee of safety. */
    riskScore: number;
    findings: ScanFinding[];
    counts: Record<FindingCategory, number>;
}
export declare function listRules(): {
    id: string;
    category: FindingCategory;
    severity: FindingSeverity;
    message: string;
}[];
/** Scan text locally. This function makes no network requests and never returns matched values. */
export declare function scanText(input: string): ScanResult;
/** Replace secrets and PII while leaving injection signals untouched for explicit review. */
export declare function redactText(input: string, result?: ScanResult): string;
//# sourceMappingURL=scanner.d.ts.map
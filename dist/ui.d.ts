export type Tone = "cyan" | "green" | "yellow" | "red" | "dim" | "bold";
export declare function useColor(tty?: boolean, env?: NodeJS.ProcessEnv): boolean;
export declare function paint(text: string, tone: Tone, enabled?: boolean): string;
export declare function safeDisplay(text: string): string;
export declare function banner(version: string, width?: number): string;
export declare function menu(version: string): string;
export interface DisplayFinding {
    severity: string;
    rule: string;
    line: number;
    column: number;
    message: string;
    suppressed: boolean;
}
export interface DisplayReport {
    file: string;
    riskScore: number;
    findings: DisplayFinding[];
}
export declare function renderReport(r: DisplayReport, color?: boolean): string[];
export declare function outcome(status: number, color?: boolean): string;
//# sourceMappingURL=ui.d.ts.map
export function listRules() { return rules.map(({ id, category, severity, message }) => ({ id, category, severity, message })); }
const rules = [
    {
        id: "bearer-token", category: "secret", severity: "high",
        message: "Authorization bearer credential-like value detected.", replacement: "[REDACTED_BEARER]",
        pattern: /\bauthorization["']?\s*[:=]\s*["']?Bearer[ \t]+([A-Za-z0-9._~+\/-]{12,}=*)/gi, captureGroups: [1],
    },
    {
        id: "jwt-token", category: "secret", severity: "high",
        message: "Signed JWT-like value detected. Claims may contain private data.", replacement: "[REDACTED_JWT]",
        pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    },
    {
        id: "database-password", category: "secret", severity: "high",
        message: "Password in a database connection URL detected.", replacement: "[REDACTED_DB_PASSWORD]",
        pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@/]+:([^\s@/]+)@/gi,
        captureGroups: [1],
    },
    {
        id: "npm-token", category: "secret", severity: "critical",
        message: "npm token-like value detected.", replacement: "[REDACTED_NPM_TOKEN]",
        pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    },
    {
        id: "gitlab-token", category: "secret", severity: "critical",
        message: "GitLab access token-like value detected.", replacement: "[REDACTED_GITLAB_TOKEN]",
        pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        id: "private-key-pem",
        category: "secret",
        severity: "critical",
        message: "Private-key material detected.",
        replacement: "[REDACTED_PRIVATE_KEY]",
        pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
    },
    {
        id: "aws-access-key-id",
        category: "secret",
        severity: "high",
        message: "AWS access-key identifier detected.",
        replacement: "[REDACTED_AWS_KEY]",
        pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    },
    {
        id: "github-token",
        category: "secret",
        severity: "critical",
        message: "GitHub token-like value detected.",
        replacement: "[REDACTED_GITHUB_TOKEN]",
        pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
    },
    {
        id: "github-fine-grained-token",
        category: "secret",
        severity: "critical",
        message: "GitHub fine-grained token-like value detected.",
        replacement: "[REDACTED_GITHUB_TOKEN]",
        pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    },
    {
        id: "anthropic-api-key",
        category: "secret",
        severity: "critical",
        message: "Anthropic API-key-like value detected.",
        replacement: "[REDACTED_API_KEY]",
        pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        id: "openai-api-key",
        category: "secret",
        severity: "critical",
        message: "OpenAI API-key-like value detected.",
        replacement: "[REDACTED_API_KEY]",
        pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    },
    {
        id: "stripe-live-secret",
        category: "secret",
        severity: "critical",
        message: "Stripe live secret-key-like value detected.",
        replacement: "[REDACTED_API_KEY]",
        pattern: /\bsk_live_[A-Za-z0-9]{20,}\b/g,
    },
    {
        id: "google-api-key",
        category: "secret",
        severity: "high",
        message: "Google API-key-like value detected.",
        replacement: "[REDACTED_API_KEY]",
        pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    },
    {
        id: "slack-token",
        category: "secret",
        severity: "high",
        message: "Slack token-like value detected.",
        replacement: "[REDACTED_SLACK_TOKEN]",
        pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    },
    {
        id: "credential-assignment",
        category: "secret",
        severity: "medium",
        message: "A credential-like assignment contains a value.",
        replacement: "[REDACTED_CREDENTIAL]",
        pattern: /\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|aws_secret_access_key|database_password)\b["']?\s*[:=]\s*(?:"([^"\r\n]{4,})"|'([^'\r\n]{4,})'|`([^`\r\n]{4,})`|([A-Za-z0-9/+_.=-]{8,}))/gi,
        captureGroups: [1, 2, 3, 4],
    },
    {
        id: "email-address",
        category: "pii",
        severity: "medium",
        message: "Email address detected.",
        replacement: "[REDACTED_EMAIL]",
        pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    },
    {
        id: "phone-number",
        category: "pii",
        severity: "medium",
        message: "Looks like a Saudi or international phone number.",
        replacement: "[REDACTED_PHONE]",
        pattern: /(?<!\d)(?:\+?966[\s-]?)?0?5(?:[\s-]?\d){8}(?!\d)|(?<!\d)\+\d{1,3}(?:[\s-]?\d){8,14}(?!\d)/g,
    },
    {
        id: "private-ipv4",
        category: "pii",
        severity: "low",
        message: "Private, loopback, or link-local IPv4 address detected.",
        replacement: "[REDACTED_PRIVATE_IP]",
        pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        accepts: isPrivateIPv4,
    },
    {
        id: "ignore-instructions",
        category: "injection",
        severity: "high",
        message: "Text resembles an attempt to override prior instructions.",
        replacement: "",
        pattern: /\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above|earlier|system|developer)\s+(?:system\s+|developer\s+)?instructions?\b/gi,
    },
    {
        id: "reveal-hidden-prompt",
        category: "injection",
        severity: "medium",
        message: "Text asks to reveal hidden system or developer instructions.",
        replacement: "",
        pattern: /\b(?:reveal|show|print|repeat|output|leak|disclose|dump)\s+(?:the\s+)?(?:hidden\s+|secret\s+)?(?:system|developer)\s+(?:prompt|instructions?)\b/gi,
    },
    {
        id: "safety-bypass",
        category: "injection",
        severity: "medium",
        message: "Text resembles an attempt to bypass safety controls.",
        replacement: "",
        pattern: /\b(?:bypass|disable|ignore|evade)\s+(?:the\s+)?(?:safety|security|content)\s+(?:filters?|guardrails?|policies|restrictions)\b/gi,
    },
    {
        id: "jailbreak-language",
        category: "injection",
        severity: "low",
        message: "Known jailbreak terminology detected; review the surrounding context.",
        replacement: "",
        pattern: /\b(?:DAN\s+mode|developer\s+mode|jailbreak(?:ing)?)\b/gi,
    },
];
const severityWeight = {
    low: 10,
    medium: 20,
    high: 35,
    critical: 45,
};
/** Scan text locally. This function makes no network requests and never returns matched values. */
export function scanText(input) {
    const findings = [];
    for (const rule of rules) {
        // RegExp instances with the global flag keep mutable lastIndex; clone for every scan.
        const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
        for (const match of input.matchAll(pattern)) {
            const whole = match[0];
            const matchStart = match.index;
            if (matchStart === undefined || (rule.accepts && !rule.accepts(whole)))
                continue;
            const captured = rule.captureGroups?.map((group) => match[group]).find((value) => value !== undefined);
            const relativeStart = captured === undefined ? 0 : whole.lastIndexOf(captured);
            const value = captured ?? whole;
            if (findings.length >= 10000)
                throw new Error("Too many findings; split the input into smaller files.");
            findings.push({
                rule: rule.id,
                category: rule.category,
                severity: rule.severity,
                message: rule.message,
                start: matchStart + relativeStart,
                end: matchStart + relativeStart + value.length,
                replacement: rule.replacement,
            });
        }
    }
    // Keep detection signals independent. Redaction merges intervals separately so
    // overlapping regexes cannot leave the tail of a secret exposed.
    const nonOverlapping = findings.sort((a, b) => a.start - b.start || b.end - a.end);
    const counts = { secret: 0, pii: 0, injection: 0 };
    for (const finding of nonOverlapping)
        counts[finding.category] += 1;
    const riskScore = Math.min(100, nonOverlapping.reduce((score, finding) => score + severityWeight[finding.severity], 0));
    return { riskScore, findings: nonOverlapping, counts };
}
/** Replace secrets and PII while leaving injection signals untouched for explicit review. */
export function redactText(input, result = scanText(input)) {
    const spans = [];
    const ordered = result.findings.filter(f => f.category !== "injection" && f.replacement)
        .sort((a, b) => a.start - b.start || b.end - a.end);
    for (const f of ordered) {
        const previous = spans[spans.length - 1];
        if (previous && f.start < previous.end) {
            if (f.end > previous.end) {
                previous.end = f.end;
                previous.replacement = "[REDACTED_SENSITIVE]";
            }
        }
        else
            spans.push({ start: f.start, end: f.end, replacement: f.replacement });
    }
    return spans.reverse().reduce((text, f) => text.slice(0, f.start) + f.replacement + text.slice(f.end), input);
}
function isPrivateIPv4(value) {
    const octets = value.split(".").map(Number);
    if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255))
        return false;
    const [a, b] = octets;
    return (a === 10 ||
        a === 127 ||
        (a === 192 && b === 168) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 169 && b === 254));
}
//# sourceMappingURL=scanner.js.map
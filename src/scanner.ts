export type Severity = "error" | "warning";

export interface Finding {
  rule_id: string;
  message: string;
  severity: Severity;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
  evidence: string;
  entropy: number | null;
}

export interface ScanResult {
  findings: Finding[];
  scanned_characters: number;
}

interface Candidate {
  ruleId: string;
  message: string;
  severity: Severity;
  start: number;
  end: number;
  value: string;
  entropy: number | null;
}

const rules: Array<{
  ruleId: string;
  message: string;
  pattern: RegExp;
}> = [
  {
    ruleId: "aws-access-key-id",
    message: "AWS access key ID detected.",
    pattern: /\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b/g,
  },
  {
    ruleId: "github-token",
    message: "GitHub token detected.",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g,
  },
  {
    ruleId: "private-key",
    message: "Private key material detected.",
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
  },
  {
    ruleId: "mongoose-url",
    message: "MongoDB URI detected.",
    pattern: /\bmongodb(?:\+srv)?:\/\/[^:/\s@]+:[^@/\s]+@[^/\s?#]+(?:\/[^\s?#]*)?(?:\?[^\s#]*)?/g,
  },
];

const assignmentPattern = /(?<![A-Za-z0-9])(?:api[_-]?(?:key|token)|secret|token|password|passwd)(?![A-Za-z0-9])\s*[:=]\s*['"]?([^\s"']{16,})/gim;
const environmentReferencePattern = /^(?:process\.env|import\.meta\.env)\.[A-Za-z_$][A-Za-z0-9_$]*;?$/i;
const tokenPattern = /(?<![A-Za-z0-9])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9])/g;
const secretContextPattern = /(?<![A-Za-z0-9])(?:api[_-]?(?:key|token)|secret|token|password|credential|auth)(?![A-Za-z0-9])/i;

export function calculateEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }

  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }

  return [...counts.values()].reduce((entropy, count) => {
    const probability = count / value.length;
    return entropy - probability * Math.log2(probability);
  }, 0);
}

export function scan(text: string): ScanResult {
  const candidates: Candidate[] = [];

  for (const rule of rules) {
    for (const match of text.matchAll(rule.pattern)) {
      const value = match[0];
      const start = match.index;
      candidates.push({
        ruleId: rule.ruleId,
        message: rule.message,
        severity: "error",
        start,
        end: start + value.length,
        value,
        entropy: null,
      });
    }
  }

  for (const match of text.matchAll(assignmentPattern)) {
    const value = match[1];
    if (environmentReferencePattern.test(value)) {
      continue;
    }

    const start = match.index + match[0].lastIndexOf(value);
    candidates.push({
      ruleId: "generic-secret-assignment",
      message: "Possible secret assigned to a sensitive variable.",
      severity: "warning",
      start,
      end: start + value.length,
      value,
      entropy: null,
    });
  }

  let lineOffset = 0;
  for (const line of text.match(/[^\n]*(?:\n|$)/g) ?? []) {
    if (line.length === 0) {
      break;
    }

    if (secretContextPattern.test(line)) {
      for (const match of line.matchAll(tokenPattern)) {
        const value = match[0];
        const entropy = calculateEntropy(value);
        if (entropy >= 3.5) {
          candidates.push({
            ruleId: "high-entropy-secret",
            message: "High-entropy value in a secret-like context.",
            severity: "warning",
            start: lineOffset + match.index,
            end: lineOffset + match.index + value.length,
            value,
            entropy: Math.round(entropy * 100) / 100,
          });
        }
      }
    }

    lineOffset += line.length;
  }

  const unique = new Map<string, Candidate>();
  for (const candidate of candidates.sort((left, right) => left.start - right.start || left.end - right.end)) {
    const key = `${candidate.start}:${candidate.end}`;
    const existing = unique.get(key);
    if (!existing) {
      unique.set(key, candidate);
    } else if (existing.entropy === null && candidate.entropy !== null) {
      unique.set(key, { ...existing, entropy: candidate.entropy });
    }
  }

  const findings = [...unique.values()].map((candidate): Finding => {
    const [line, column] = lineAndColumn(text, candidate.start);
    const [endLine, endColumn] = lineAndColumn(text, candidate.end);
    return {
      rule_id: candidate.ruleId,
      message: candidate.message,
      severity: candidate.severity,
      line,
      column,
      end_line: endLine,
      end_column: endColumn,
      evidence: candidate.value,
      entropy: candidate.entropy,
    };
  });

  return { findings, scanned_characters: text.length };
}

function lineAndColumn(text: string, offset: number): [number, number] {
  const before = text.slice(0, offset);
  const line = (before.match(/\n/g) ?? []).length;
  return [line, offset - (before.lastIndexOf("\n") + 1)];
}
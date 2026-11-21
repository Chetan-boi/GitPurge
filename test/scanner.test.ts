import assert from "node:assert/strict";
import test from "node:test";
import { createGitIgnoreMatcher } from "../src/gitignore";
import { calculateEntropy, scan } from "../src/scanner";

test("matches the checked-in sample result", () => {
  const text = "API_KEY = 'SK-12345678901234567890123456789012'";
  const result = scan(text);

  assert.equal(result.scanned_characters, 47);
  assert.deepEqual(result.findings, [
    {
      rule_id: "generic-secret-assignment",
      message: "Possible secret assigned to a sensitive variable.",
      severity: "warning",
      line: 0,
      column: 11,
      end_line: 0,
      end_column: 46,
      evidence: "SK-12345678901234567890123456789012",
      entropy: 3.59,
    },
  ]);
});

test("detects secrets in compound environment variable names", () => {
  const result = scan([
    "OPENAI_API_KEY=sk-live_$:@1234567890abcd",
    "JWT_ADMIN_SECRET=jwt.secret-$:@1234567890#;",
  ].join("\n"));

  assert.deepEqual(result.findings.map(({ rule_id, line }) => ({ rule_id, line })), [
    { rule_id: "generic-secret-assignment", line: 0 },
    { rule_id: "generic-secret-assignment", line: 1 },
  ]);
});

test("does not report direct environment-variable references as secrets", () => {
  const result = scan("const JWT_ADMIN_SECRET = process.env.JWT_ADMIN_SECRET;");

  assert.equal(result.findings.length, 0);
});

test("matches .gitignore rules in standalone workspaces", () => {
  const isIgnored = createGitIgnoreMatcher(".env\nnode_modules/\n");

  assert.equal(isIgnored(".env"), true);
  assert.equal(isIgnored("nested/node_modules/package.json"), true);
  assert.equal(isIgnored(".env.example"), false);
});

test("detects known token formats and private-key markers", () => {
  const result = scan([
    "AKIA1234567890ABCDEF",
    `ghp_${"a".repeat(36)}`,
    "-----BEGIN RSA PRIVATE KEY-----",
  ].join("\n"));

  assert.deepEqual(result.findings.map((finding) => finding.rule_id), [
    "aws-access-key-id",
    "github-token",
    "private-key",
  ]);
  assert.deepEqual(result.findings.map((finding) => finding.line), [0, 1, 2]);
});

test("detects authenticated MongoDB connection URLs", () => {
  const uri = "mongodb+srv://demo:dummy-secret-123@db.example.test/app?retryWrites=true";
  const result = scan(`MONGOOSE_URL=${uri}`);

  assert.deepEqual(result.findings.map(({ rule_id, severity, evidence }) => ({ rule_id, severity, evidence })), [
    { rule_id: "mongoose-url", severity: "error", evidence: uri },
  ]);
});

test("reports high entropy values only in secret-like context", () => {
  const token = "aBcDeF0123456789+/XYZ";
  const contextual = scan(`credential: ${token}`);
  const neutral = scan(token);

  assert.equal(contextual.findings[0].rule_id, "high-entropy-secret");
  assert.equal(contextual.findings[0].entropy, Math.round(calculateEntropy(token) * 100) / 100);
  assert.equal(neutral.findings.length, 0);
});

test("reports zero-based positions over multiple lines", () => {
  const finding = scan(`nothing\napi_key = "${"Z".repeat(24)}"`).findings[0];

  assert.equal(finding.line, 1);
  assert.equal(finding.column, 11);
  assert.equal(finding.end_line, 1);
  assert.equal(finding.end_column, 35);
});
// Fixtures are assembled at runtime so this file never contains a literal
// that secret scanners would flag.
const providerSamples: Array<[string, string]> = [
  ["slack-token", "xoxb-" + "1234567890-" + "abcdefghij"],
  ["stripe-api-key", "sk_" + "live_" + "a".repeat(24)],
  ["google-api-key", "AIza" + "A".repeat(35)],
  ["postgres-url", "postgres://admin:hunter2@db.example.com:5432/app"],
  ["mysql-url", "mysql://root:hunter2@db.example.com/app"],
  ["openai-api-key", "sk-" + "A1b2C3d4".repeat(5)],
  ["anthropic-api-key", "sk-ant-api03-" + "A1b2C3d4".repeat(10)],
  ["sendgrid-api-key", "SG." + "a".repeat(22) + "." + "b".repeat(43)],
  ["discord-bot-token", "M" + "a".repeat(23) + "." + "b".repeat(6) + "." + "c".repeat(27)],
];

for (const [ruleId, secret] of providerSamples) {
  test(`detects ${ruleId}`, () => {
    const result = scan(`value = ${secret}\n`);
    const finding = result.findings.find((item) => item.rule_id === ruleId);

    assert.ok(finding, `expected ${ruleId} to be reported`);
    assert.equal(finding.severity, "error");
    assert.equal(finding.evidence, secret);
  });
}

test("reports AWS secret access key assignments as warnings", () => {
  const finding = scan(`aws_secret_access_key = "${"A".repeat(40)}"`).findings.find(
    (item) => item.rule_id === "aws-secret-access-key",
  );

  assert.ok(finding);
  assert.equal(finding.severity, "warning");
});

test("labels Anthropic keys as Anthropic rather than OpenAI", () => {
  const key = "sk-ant-api03-" + "A1b2C3d4".repeat(10);

  assert.deepEqual(scan(`value = ${key}`).findings.map((item) => item.rule_id), ["anthropic-api-key"]);
});

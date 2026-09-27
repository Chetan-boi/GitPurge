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
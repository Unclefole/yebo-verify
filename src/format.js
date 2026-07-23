/**
 * Human-readable output formatting for verification results.
 * Plain text, no color dependencies (ANSI used only when stdout is a TTY).
 */

const FIELD_EXPLANATIONS = [
  [
    "mandate_id",
    "Unique identifier of this mandate. Use it to trace the item back to the system of record and to your sample selection.",
  ],
  [
    "subject_identity",
    "The machine actor (agent or automation) that requested the action. This is who asked - not who approved.",
  ],
  [
    "counterparty_identity",
    "The payee: the vendor or account the funds were directed to. Covered by the signed hash - it cannot be swapped after approval.",
  ],
  [
    "capability",
    "The action that was authorized (for example transfer.funds). An approval for one capability cannot be reused for another.",
  ],
  [
    "amount / currency",
    "The exact amount approved, in minor units (e.g. cents). Covered by the signed hash - altering the amount after approval makes verification fail.",
  ],
  [
    "policy_hash",
    "A digest of the exact policy version in force when the approval was made. Lets you confirm which control configuration governed this item.",
  ],
  [
    "nonce",
    "A single-use random value. Prevents the same approval from being replayed for a second execution.",
  ],
  [
    "issued_at / expires_at",
    "The validity window of the mandate. An approval is bound to a specific, short-lived request - not an open-ended permission.",
  ],
  [
    "approval.approved_by",
    "The human approver. For control testing, match this identity to your delegation of authority for the period.",
  ],
  [
    "approval.mandate_hash",
    "The content hash of the mandate at the moment of approval. The verifier recomputes this from the mandate fields and compares.",
  ],
  [
    "approval.timestamp",
    "When the approval signature was produced. Use it to test timeliness (approval precedes execution).",
  ],
  [
    "approval.signature",
    "ECDSA P-256 signature over (mandate hash : policy hash : timestamp). Verifiable with the public key alone - no vendor access required.",
  ],
];

/**
 * Format a verification result for terminal output.
 * @param {{ pass: boolean, checks: Array, failures: string[] }} result
 * @param {object|null} artifact  parsed artifact (null if unreadable)
 * @param {{ artifactPath: string, keyPath: string, explain: boolean, tty: boolean }} opts
 * @returns {string}
 */
export function formatResult(result, artifact, opts) {
  const lines = [];
  const bold = (s) => (opts.tty ? `\x1b[1m${s}\x1b[0m` : s);
  const green = (s) => (opts.tty ? `\x1b[32m${s}\x1b[0m` : s);
  const red = (s) => (opts.tty ? `\x1b[31m${s}\x1b[0m` : s);

  lines.push("");
  lines.push(bold("YEBO MANDATE VERIFICATION"));
  lines.push("");
  lines.push(`  artifact  ${opts.artifactPath}`);
  lines.push(`  key       ${opts.keyPath}`);
  lines.push("");
  lines.push(
    result.pass
      ? `  ${bold(green("RESULT: PASS"))} - the artifact is exactly what the approver signed.`
      : `  ${bold(red("RESULT: FAIL"))} - this artifact does not verify.`
  );
  lines.push("");

  if (artifact?.mandate && artifact?.approval) {
    const m = artifact.mandate;
    const a = artifact.approval;
    lines.push(bold("  Field breakdown"));
    pushField(lines, "action", m.capability);
    pushField(lines, "amount", formatAmount(m.amount, m.currency));
    pushField(lines, "payee", m.counterparty_identity);
    pushField(lines, "requested by", m.subject_identity);
    pushField(lines, "approver", a.approved_by);
    pushField(lines, "policy version", `sha256:${truncate(m.policy_hash)}`);
    pushField(lines, "approved at", a.timestamp);
    pushField(lines, "valid window", `${m.issued_at} → ${m.expires_at}`);
    pushField(lines, "mandate id", m.mandate_id);
    const sig = result.checks.find((c) => c.id === "signature");
    pushField(
      lines,
      "signature",
      sig?.ok ? "VALID (ECDSA P-256 / SHA-256)" : "INVALID"
    );
    lines.push("");
  }

  lines.push(bold("  Checks"));
  for (const check of result.checks) {
    const mark = check.ok ? green("PASS") : red("FAIL");
    lines.push(`  [${mark}] ${check.label}`);
    lines.push(`         ${check.detail}`);
  }
  lines.push("");

  if (!result.pass) {
    lines.push(bold(red("  What did not verify:")));
    for (const f of result.failures) {
      lines.push(`   - ${FAILURE_NAMES[f] ?? f}`);
    }
    lines.push("");
  }

  if (opts.explain) {
    lines.push(bold("  Field reference (audit terms)"));
    for (const [field, meaning] of FIELD_EXPLANATIONS) {
      lines.push(`  ${field}`);
      lines.push(`      ${meaning}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

const FAILURE_NAMES = {
  malformed_artifact:
    "malformed artifact - the file is not a complete mandate artifact",
  malformed_key: "unreadable public key - the key file is not valid PEM",
  wrong_key:
    "wrong key - the supplied public key is not the key this artifact references",
  tampered_mandate:
    "tampered mandate - the contents differ from what the approver signed",
  policy_hash_mismatch:
    "policy mismatch - the mandate references a different policy version than the one approved",
  bad_signature:
    "bad signature - the approval signature does not verify under the supplied key",
};

function pushField(lines, label, value) {
  if (value === undefined || value === null || value === "") return;
  lines.push(`  ${label.padEnd(16)}${value}`);
}

function formatAmount(amount, currency) {
  if (amount === undefined) return undefined;
  const major = (amount / 100).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
  return `${major} ${currency ?? ""}`.trim() + ` (${amount} minor units)`;
}

function truncate(hex) {
  return typeof hex === "string" && hex.length > 20 ? `${hex.slice(0, 20)}…` : String(hex);
}

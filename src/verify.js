/**
 * Verification of a Yebo mandate artifact.
 *
 * A mandate artifact is a JSON document with two parts:
 *
 *   mandate   - what the machine asked to do (action, amount, payee,
 *               requesting agent, policy hash, validity window, nonce)
 *   approval  - what a human authorized: the mandate's content hash, the
 *               policy hash, an approval timestamp, and an ECDSA P-256
 *               signature over exactly those three values
 *
 * Verification is four independent checks:
 *
 *   1. structure          the artifact is well-formed and complete
 *   2. mandate_integrity  recomputing the mandate hash reproduces the hash
 *                         that was signed at approval time - any edit to any
 *                         covered field (including the amount) changes the
 *                         hash and fails this check
 *   3. policy_binding     the policy hash inside the mandate matches the
 *                         policy hash the approver signed
 *   4. signature          the ECDSA signature over
 *                         "<mandate_hash>:<policy_hash>:<timestamp>"
 *                         verifies under the supplied public key
 *
 * Everything runs locally. This module performs no I/O of any kind - it
 * imports only `node:crypto` and takes plain values as input.
 */
import { createVerify } from "node:crypto";
import {
  computeMandateHash,
  keyFingerprint,
  REQUIRED_HASH_FIELDS,
  OPTIONAL_HASH_FIELDS,
} from "./canonical.js";

const REQUIRED_MANDATE_FIELDS = REQUIRED_HASH_FIELDS;
const REQUIRED_APPROVAL_FIELDS = [
  "approved_by",
  "mandate_hash",
  "policy_hash",
  "timestamp",
  "signature",
];

/**
 * @typedef {object} Check
 * @property {string} id       machine-readable check id
 * @property {string} label    human-readable check name
 * @property {boolean} ok
 * @property {string} detail   what was checked / why it failed
 */

/**
 * Verify a parsed mandate artifact against a PEM public key.
 *
 * @param {object} artifact       parsed artifact JSON
 * @param {string} publicKeyPem   PEM-encoded (SPKI) P-256 public key
 * @returns {{ pass: boolean, checks: Check[], failures: string[] }}
 */
export function verifyArtifact(artifact, publicKeyPem) {
  const checks = [];
  const failures = [];

  // ── Check 1: structure ─────────────────────────────────────────────────
  const structureProblems = [];
  if (typeof artifact !== "object" || artifact === null) {
    structureProblems.push("artifact is not a JSON object");
  } else {
    if (typeof artifact.mandate !== "object" || artifact.mandate === null) {
      structureProblems.push('missing "mandate" object');
    }
    if (typeof artifact.approval !== "object" || artifact.approval === null) {
      structureProblems.push('missing "approval" object');
    }
  }
  if (structureProblems.length === 0) {
    for (const f of REQUIRED_MANDATE_FIELDS) {
      if (artifact.mandate[f] === undefined || artifact.mandate[f] === null) {
        structureProblems.push(`missing mandate field "${f}"`);
      }
    }
    for (const f of REQUIRED_APPROVAL_FIELDS) {
      if (artifact.approval[f] === undefined || artifact.approval[f] === null) {
        structureProblems.push(`missing approval field "${f}"`);
      }
    }
  }
  const structureOk = structureProblems.length === 0;
  checks.push({
    id: "structure",
    label: "Artifact structure",
    ok: structureOk,
    detail: structureOk
      ? "All required mandate and approval fields are present."
      : `Malformed artifact: ${structureProblems.join("; ")}.`,
  });
  if (!structureOk) {
    failures.push("malformed_artifact");
    return { pass: false, checks, failures };
  }

  const { mandate, approval } = artifact;

  // ── Key sanity + fingerprint diagnosis (not a signed property) ─────────
  let providedFingerprint = null;
  try {
    providedFingerprint = keyFingerprint(publicKeyPem);
  } catch {
    checks.push({
      id: "key",
      label: "Public key",
      ok: false,
      detail: "The supplied public key is not readable PEM.",
    });
    failures.push("malformed_key");
    return { pass: false, checks, failures };
  }
  if (
    typeof approval.key_fingerprint === "string" &&
    approval.key_fingerprint.length > 0 &&
    approval.key_fingerprint !== providedFingerprint
  ) {
    checks.push({
      id: "key",
      label: "Public key",
      ok: false,
      detail:
        "The supplied public key is not the key this artifact references " +
        `(artifact expects fingerprint ${short(approval.key_fingerprint)}, ` +
        `supplied key has fingerprint ${short(providedFingerprint)}). ` +
        "You are verifying with the wrong key.",
    });
    failures.push("wrong_key");
  } else {
    checks.push({
      id: "key",
      label: "Public key",
      ok: true,
      detail: `Key fingerprint ${short(providedFingerprint)} accepted for verification.`,
    });
  }

  // ── Check 2: mandate integrity ─────────────────────────────────────────
  const recomputedHash = computeMandateHash(mandate);
  const integrityOk = recomputedHash === approval.mandate_hash;
  checks.push({
    id: "mandate_integrity",
    label: "Mandate integrity",
    ok: integrityOk,
    detail: integrityOk
      ? `Recomputed mandate hash ${short(recomputedHash)} matches the hash signed at approval.`
      : "The mandate contents do NOT match what was approved. " +
        `Recomputed hash ${short(recomputedHash)} differs from the signed hash ` +
        `${short(approval.mandate_hash)}. One or more of these fields has been ` +
        `altered since approval: ${[...REQUIRED_HASH_FIELDS, ...OPTIONAL_HASH_FIELDS].join(", ")}.`,
  });
  if (!integrityOk) failures.push("tampered_mandate");

  // ── Check 3: policy binding ────────────────────────────────────────────
  const policyOk = mandate.policy_hash === approval.policy_hash;
  checks.push({
    id: "policy_binding",
    label: "Policy binding",
    ok: policyOk,
    detail: policyOk
      ? "The policy hash in the mandate matches the policy hash the approver signed."
      : "The policy hash in the mandate does not match the policy hash in the " +
        "approval. The mandate references a different policy version than the one approved.",
  });
  if (!policyOk) failures.push("policy_hash_mismatch");

  // ── Check 4: approval signature ────────────────────────────────────────
  // The signature covers the values as recorded in the approval block. If the
  // mandate was tampered with, check 2 already fails; this check answers a
  // separate question: is the approval itself authentic under this key?
  let signatureOk = false;
  let signatureDetail;
  try {
    const signable = [
      approval.mandate_hash,
      approval.policy_hash,
      approval.timestamp,
    ].join(":");
    const verifier = createVerify("sha256");
    verifier.update(signable, "utf8");
    signatureOk = verifier.verify(publicKeyPem, approval.signature, "base64url");
    signatureDetail = signatureOk
      ? "ECDSA P-256 signature over (mandate hash : policy hash : timestamp) is valid under the supplied key."
      : failures.includes("wrong_key")
        ? "Signature does not verify under the supplied key (which is not the key the artifact references)."
        : "Signature does NOT verify under the supplied key. Either the approval " +
          "block was altered, the signature is forged, or this is not the signer's public key.";
  } catch (err) {
    signatureDetail = `Signature verification errored: ${err instanceof Error ? err.message : String(err)}.`;
  }
  checks.push({
    id: "signature",
    label: "Approval signature",
    ok: signatureOk,
    detail: signatureDetail,
  });
  if (!signatureOk) failures.push("bad_signature");

  return { pass: failures.length === 0, checks, failures };
}

function short(hex) {
  return typeof hex === "string" && hex.length > 16 ? `${hex.slice(0, 16)}…` : String(hex);
}

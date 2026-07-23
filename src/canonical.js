/**
 * Canonical mandate hashing.
 *
 * A mandate's content hash is a SHA-256 digest over a deterministic JSON
 * serialization of its fields: keys are sorted alphabetically, and optional
 * fields (amount, currency) are included only when present. Identical mandate
 * contents always produce the identical hash, on any machine, forever.
 *
 * This is the complete integrity rule. There is nothing hidden in it:
 * if you re-implement these ~20 lines in any language, you will get the
 * same hash from the same artifact.
 */
import { createHash } from "node:crypto";

/** Fields always covered by the mandate hash. */
export const REQUIRED_HASH_FIELDS = [
  "mandate_id",
  "subject_identity",
  "counterparty_identity",
  "capability",
  "policy_hash",
  "nonce",
  "issued_at",
  "expires_at",
];

/** Fields covered by the mandate hash when present. */
export const OPTIONAL_HASH_FIELDS = ["amount", "currency"];

/**
 * Recompute the canonical content hash of a mandate.
 * @param {object} mandate
 * @returns {string} lowercase hex SHA-256 digest
 */
export function computeMandateHash(mandate) {
  const input = {};
  for (const field of REQUIRED_HASH_FIELDS) {
    input[field] = mandate[field];
  }
  for (const field of OPTIONAL_HASH_FIELDS) {
    if (mandate[field] !== undefined) {
      input[field] = mandate[field];
    }
  }
  const canonical = JSON.stringify(input, Object.keys(input).sort());
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Compute a stable fingerprint of a PEM public key (SHA-256 over the DER
 * bytes, hex-encoded). Used only to distinguish "wrong key supplied" from
 * "signature does not verify" in failure output.
 * @param {string} pem
 * @returns {string} lowercase hex SHA-256 digest of the DER key bytes
 */
export function keyFingerprint(pem) {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(base64, "base64");
  return createHash("sha256").update(der).digest("hex");
}

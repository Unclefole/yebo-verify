/**
 * Tests for yebo-verify.
 *
 * Fixtures are produced in-test with the same signing scheme production
 * mandates use: an ECDSA P-256 key signs SHA-256 over
 * "<mandate_hash>:<policy_hash>:<timestamp>", where mandate_hash is the
 * canonical SHA-256 of the mandate's covered fields.
 *
 * The critical cases:
 *   - a valid artifact PASSES
 *   - a tampered amount FAILS (mandate integrity)
 *   - a wrong public key FAILS (wrong key / bad signature)
 *   - malformed artifacts FAIL with named reasons
 */
import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createSign } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyArtifact } from "../src/verify.js";
import { computeMandateHash, keyFingerprint } from "../src/canonical.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "bin", "verify.js");

function makeKeyPair() {
  return generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function makeArtifact({ privateKey, publicKey }) {
  const mandate = {
    mandate_id: "9f8e7d6c-0000-4000-8000-1234567890ab",
    subject_identity: "agent:ops-runner-3",
    counterparty_identity: "vendor:northwind-industrial",
    capability: "transfer.funds",
    policy_hash: "b2f1c4aa90d3e8f7a6c5b4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3",
    nonce: "5e884898da28047151d0e56f8dc62927",
    issued_at: "2026-07-20T17:03:12.000Z",
    expires_at: "2026-07-20T17:08:12.000Z",
    amount: 1850000,
    currency: "USD",
  };
  const mandate_hash = computeMandateHash(mandate);
  const timestamp = "2026-07-20T17:04:41.000Z";
  const signable = [mandate_hash, mandate.policy_hash, timestamp].join(":");
  const signer = createSign("sha256");
  signer.update(signable, "utf8");
  const signature = signer.sign(privateKey, "base64url");
  return {
    artifact_type: "yebo.mandate.artifact",
    artifact_version: "1.0",
    mandate,
    approval: {
      approved_by: "cfo@acme.example",
      mandate_hash,
      policy_hash: mandate.policy_hash,
      timestamp,
      signature,
      algorithm: "ECDSA-P256-SHA256",
      key_fingerprint: keyFingerprint(publicKey),
    },
  };
}

test("valid artifact PASSES with a full set of green checks", () => {
  const keys = makeKeyPair();
  const artifact = makeArtifact(keys);
  const result = verifyArtifact(artifact, keys.publicKey);
  assert.equal(result.pass, true);
  assert.deepEqual(result.failures, []);
  for (const check of result.checks) {
    assert.equal(check.ok, true, `check ${check.id} should pass: ${check.detail}`);
  }
});

test("tampered amount FAILS mandate integrity", () => {
  const keys = makeKeyPair();
  const artifact = makeArtifact(keys);
  // The attack this tool exists to catch: alter the approved amount.
  artifact.mandate.amount = 9850000;
  const result = verifyArtifact(artifact, keys.publicKey);
  assert.equal(result.pass, false);
  assert.ok(result.failures.includes("tampered_mandate"));
  // The approval itself is still authentic - only the mandate was altered.
  const sig = result.checks.find((c) => c.id === "signature");
  assert.equal(sig.ok, true);
});

test("tampered payee FAILS mandate integrity", () => {
  const keys = makeKeyPair();
  const artifact = makeArtifact(keys);
  artifact.mandate.counterparty_identity = "vendor:attacker-shell-co";
  const result = verifyArtifact(artifact, keys.publicKey);
  assert.equal(result.pass, false);
  assert.ok(result.failures.includes("tampered_mandate"));
});

test("wrong public key FAILS and is named as wrong key", () => {
  const keys = makeKeyPair();
  const otherKeys = makeKeyPair();
  const artifact = makeArtifact(keys);
  const result = verifyArtifact(artifact, otherKeys.publicKey);
  assert.equal(result.pass, false);
  assert.ok(result.failures.includes("wrong_key"));
  assert.ok(result.failures.includes("bad_signature"));
});

test("forged signature FAILS signature check", () => {
  const keys = makeKeyPair();
  const artifact = makeArtifact(keys);
  const sig = artifact.approval.signature;
  // Flip a character in the middle of the signature.
  const i = Math.floor(sig.length / 2);
  artifact.approval.signature =
    sig.slice(0, i) + (sig[i] === "A" ? "B" : "A") + sig.slice(i + 1);
  const result = verifyArtifact(artifact, keys.publicKey);
  assert.equal(result.pass, false);
  assert.ok(result.failures.includes("bad_signature"));
});

test("tampered approval timestamp FAILS signature check", () => {
  const keys = makeKeyPair();
  const artifact = makeArtifact(keys);
  artifact.approval.timestamp = "2026-07-21T09:00:00.000Z";
  const result = verifyArtifact(artifact, keys.publicKey);
  assert.equal(result.pass, false);
  assert.ok(result.failures.includes("bad_signature"));
});

test("missing fields FAIL as malformed artifact", () => {
  const keys = makeKeyPair();
  const artifact = makeArtifact(keys);
  delete artifact.mandate.nonce;
  const result = verifyArtifact(artifact, keys.publicKey);
  assert.equal(result.pass, false);
  assert.deepEqual(result.failures, ["malformed_artifact"]);
});

test("non-object artifact FAILS as malformed", () => {
  const keys = makeKeyPair();
  const result = verifyArtifact("not an artifact", keys.publicKey);
  assert.equal(result.pass, false);
  assert.deepEqual(result.failures, ["malformed_artifact"]);
});

test("unreadable key FAILS as malformed key", () => {
  const keys = makeKeyPair();
  const artifact = makeArtifact(keys);
  const result = verifyArtifact(artifact, "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----");
  assert.equal(result.pass, false);
  // base64 decode is lenient; the failure surfaces at signature verification
  // or key parsing depending on Node version - either way it must FAIL.
  assert.ok(result.failures.length > 0);
});

test("CLI end-to-end: PASS exits 0, tampered exits 1, wrong key exits 1", () => {
  const keys = makeKeyPair();
  const otherKeys = makeKeyPair();
  const artifact = makeArtifact(keys);
  const tampered = structuredClone(artifact);
  tampered.mandate.amount = 9850000;

  const dir = mkdtempSync(join(tmpdir(), "yebo-verify-"));
  const artifactPath = join(dir, "mandate.json");
  const tamperedPath = join(dir, "mandate-tampered.json");
  const keyPath = join(dir, "key.pem");
  const wrongKeyPath = join(dir, "wrong-key.pem");
  writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
  writeFileSync(tamperedPath, JSON.stringify(tampered, null, 2));
  writeFileSync(keyPath, keys.publicKey);
  writeFileSync(wrongKeyPath, otherKeys.publicKey);

  // PASS case - exit 0, output contains PASS
  const out = execFileSync(process.execPath, [CLI, artifactPath, "--key", keyPath], {
    encoding: "utf8",
  });
  assert.match(out, /RESULT: PASS/);

  // Tampered case - exit 1
  assert.throws(
    () => execFileSync(process.execPath, [CLI, tamperedPath, "--key", keyPath], { encoding: "utf8" }),
    (err) => {
      assert.equal(err.status, 1);
      assert.match(err.stdout, /RESULT: FAIL/);
      assert.match(err.stdout, /tampered mandate/);
      return true;
    }
  );

  // Wrong key case - exit 1
  assert.throws(
    () => execFileSync(process.execPath, [CLI, artifactPath, "--key", wrongKeyPath], { encoding: "utf8" }),
    (err) => {
      assert.equal(err.status, 1);
      assert.match(err.stdout, /RESULT: FAIL/);
      assert.match(err.stdout, /wrong key/);
      return true;
    }
  );
});

test("verifier source has no network imports", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const srcDir = join(__dirname, "..", "src");
  const files = readdirSync(srcDir).map((f) => join(srcDir, f));
  files.push(CLI);
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    for (const banned of ["node:http", "node:https", "node:net", "node:dns", "fetch("]) {
      assert.ok(
        !source.includes(banned),
        `${file} must not reference ${banned} - the verifier is offline-only`
      );
    }
  }
});

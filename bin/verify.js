#!/usr/bin/env node
/**
 * yebo-verify - verify a Yebo mandate artifact offline.
 *
 *   npx @yebo/verify mandate.json --key public-key.pem
 *   npx @yebo/verify mandate.json --key public-key.pem --explain
 *   npx @yebo/verify mandate.json --key public-key.pem --json
 *
 * Exit codes: 0 = PASS, 1 = FAIL, 2 = usage / file error.
 *
 * This tool makes no network calls. It reads the two files you give it and
 * runs cryptographic checks locally with Node's built-in crypto module.
 */
import { readFileSync } from "node:fs";
import { verifyArtifact } from "../src/verify.js";
import { formatResult } from "../src/format.js";

const USAGE = `Usage: yebo-verify <mandate.json> --key <public-key.pem> [--explain] [--json]

  <mandate.json>   path to the mandate artifact to verify
  --key <pem>      path to the signer's PEM public key
  --explain        include a plain-language explanation of every field
  --json           machine-readable output
`;

function main() {
  const args = process.argv.slice(2);
  let artifactPath = null;
  let keyPath = null;
  let explain = false;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--key") {
      keyPath = args[++i];
    } else if (arg === "--explain") {
      explain = true;
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (!artifactPath) {
      artifactPath = arg;
    } else {
      process.stderr.write(`Unexpected argument: ${arg}\n\n${USAGE}`);
      process.exit(2);
    }
  }

  if (!artifactPath || !keyPath) {
    process.stderr.write(USAGE);
    process.exit(2);
  }

  let rawArtifact;
  try {
    rawArtifact = readFileSync(artifactPath, "utf8");
  } catch {
    process.stderr.write(`Cannot read artifact file: ${artifactPath}\n`);
    process.exit(2);
  }

  let publicKeyPem;
  try {
    publicKeyPem = readFileSync(keyPath, "utf8");
  } catch {
    process.stderr.write(`Cannot read key file: ${keyPath}\n`);
    process.exit(2);
  }

  let artifact = null;
  let result;
  try {
    artifact = JSON.parse(rawArtifact);
    result = verifyArtifact(artifact, publicKeyPem);
  } catch {
    result = {
      pass: false,
      checks: [
        {
          id: "structure",
          label: "Artifact structure",
          ok: false,
          detail: "The artifact file is not valid JSON.",
        },
      ],
      failures: ["malformed_artifact"],
    };
  }

  if (json) {
    process.stdout.write(JSON.stringify({ pass: result.pass, failures: result.failures, checks: result.checks }, null, 2) + "\n");
  } else {
    process.stdout.write(
      formatResult(result, artifact, {
        artifactPath,
        keyPath,
        explain,
        tty: process.stdout.isTTY === true,
      }) + "\n"
    );
  }

  process.exit(result.pass ? 0 : 1);
}

main();

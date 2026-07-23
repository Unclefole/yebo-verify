# yebo-verify

Verify a Yebo mandate artifact yourself - offline, with no account, no API
key, and no access to Yebo's systems. One artifact, one public key, one
command.

This tool exists so that an auditor, regulator, or counterparty can
independently confirm - years after the fact, even if Yebo no longer exists -
that a specific human approved a specific payment under a specific policy.

## What you need

1. **A mandate artifact** - a JSON file exported from the system of record
   (for example `mandate.json`).
2. **The signer's public key** - a PEM file (for example `public-key.pem`).

Sample files you can try right now ship with this repository in
[`examples/`](./examples/) and are also published at
[yebo.dev/verify](https://yebo.dev/verify). The Yebo public key for those
samples is [`examples/sample-public-key.pem`](./examples/sample-public-key.pem);
for production mandates, obtain the signer's public key from your system of
record or from [yebo.dev/verify](https://yebo.dev/verify).

## Requirements

- Node.js 18 or newer ([nodejs.org](https://nodejs.org)). Nothing else.
- No internet connection is needed to verify. The tool makes zero network
  calls - you can run it on an air-gapped machine.

## Run it

```bash
npx yebo-verify mandate.json --key public-key.pem
```

On success you will see:

```
YEBO MANDATE VERIFICATION

  RESULT: PASS - the artifact is exactly what the approver signed.

  Field breakdown
  action          transfer.funds
  amount          18,500.00 USD (1850000 minor units)
  payee           vendor:northwind-industrial
  requested by    agent:ops-runner-3
  approver        cfo@acme.example
  ...
  signature       VALID (ECDSA P-256 / SHA-256)
```

On failure you will see `RESULT: FAIL` and a plain-language statement of
exactly what did not verify - a tampered mandate, a bad signature, a wrong
key, or a malformed artifact.

Add `--explain` to print what each field means in audit terms:

```bash
npx yebo-verify mandate.json --key public-key.pem --explain
```

Add `--json` for machine-readable output.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | PASS - the artifact verifies |
| `1`  | FAIL - the artifact does not verify |
| `2`  | Usage or file error (missing argument, unreadable file) |

The exit code is machine-readable, so the tool can be scripted into your own
testing workpapers - a full audit sample can be verified in one loop.

## Worked example

The repository ships a real, production-signed sample mandate (an
AI-initiated vendor disbursement of $18,500.00, over threshold, approved by a
human) and a deliberately tampered copy of the same artifact with the amount
altered after approval.

Verify the genuine artifact - this must PASS:

```bash
npx yebo-verify examples/sample-mandate.json --key examples/sample-public-key.pem
# ... RESULT: PASS - the artifact is exactly what the approver signed.
# exit code 0
```

Verify the tampered copy with the same key - this must FAIL:

```bash
npx yebo-verify examples/sample-mandate-tampered.json --key examples/sample-public-key.pem
# ... RESULT: FAIL - this artifact does not verify.
# [FAIL] Mandate integrity - the contents do NOT match what was approved.
# exit code 1
```

The approval signature in the tampered copy is still authentic - but the
artifact no longer matches what the approver signed, so verification fails
and says exactly why. That is the property an approval control depends on.

## What verification proves

The artifact has two parts:

- **mandate** - what the machine asked to do: the action, the exact amount,
  the payee, the requesting agent, the policy version in force, and a
  single-use validity window.
- **approval** - what a human authorized: a cryptographic hash of the mandate
  contents, the policy hash, a timestamp, and an ECDSA P-256 signature over
  exactly those three values.

The verifier runs four checks:

1. **Artifact structure** - the file is complete and well-formed.
2. **Mandate integrity** - recomputing the mandate's content hash reproduces
   the hash that was signed. Editing *any* covered field - including the
   amount or the payee - changes the hash and fails this check.
3. **Policy binding** - the policy version inside the mandate is the policy
   version the approver signed.
4. **Approval signature** - the signature verifies under the public key you
   supplied. If it does, the approval is authentic; if not, it is forged,
   altered, or you have the wrong key.

There is no hidden step. The canonicalization rule is ~20 lines of code in
[`src/canonical.js`](./src/canonical.js) and can be re-implemented in any
language.

## What verification does not prove

- It does not prove the approver was *entitled* to approve. Match
  `approval.approved_by` against the delegation of authority for the period -
  that step belongs to your control testing, not to cryptography.
- It does not prove funds actually moved. Match `mandate_id` against the
  system of record / bank statement for the item.

## Try to break it

A check that cannot fail proves nothing. Take a passing artifact, change the
amount by one cent, and run the same command - it must FAIL with "tampered
mandate". A ready-made tampered artifact ships in
[`examples/sample-mandate-tampered.json`](./examples/sample-mandate-tampered.json),
and the same samples are published at [yebo.dev/verify](https://yebo.dev/verify).

## Tests

```bash
npm test
```

The suite includes a deliberately tampered artifact (altered amount) that
must fail, a wrong-key case that must fail, and a source check asserting the
package contains no networking code.

## License

MIT - see [LICENSE](./LICENSE).

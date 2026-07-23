/**
 * @yebo/verify - standalone, offline verifier for Yebo mandate artifacts.
 *
 * Programmatic API. The CLI in bin/verify.js is a thin wrapper around this.
 * Imports only node:crypto. No network. No configuration. No account.
 */
export { verifyArtifact } from "./verify.js";
export { computeMandateHash, keyFingerprint } from "./canonical.js";
export { formatResult } from "./format.js";

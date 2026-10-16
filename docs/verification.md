# Verification

Command: `npm test` with Node.js 24.13.0, ethers 6.17.0, and hash-wasm 4.12.0 available in the isolated validation environment.

**13 tests passed; 0 failed or skipped.** Checks cover creator material/proof behavior, exhausted/invalid inputs, password KDF and chain derivation, signer context binding, and EIP-712 request/error paths.

One test initially expected an obsolete error string. The test was aligned with the existing exhausted-proof rejection message in both this extraction and the application source. No authorization algorithm changed; the provenance manifest records the test adjustment.

The legacy authorization file and Solidity verifier source are included but these Node tests do not establish full test coverage, Solidity compilation, onchain integration, or independent cryptographic review.

All copied file digests are checked against `SOURCE_MANIFEST.json`. Registry version/license metadata was checked for declared dependencies. Only helper-validation dependencies were installed in the isolated environment; full transitive contract dependency resolution/audit is not claimed.

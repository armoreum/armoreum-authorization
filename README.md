# Armoreum Authorization

Hash-chain authorization, password-derived creator material, EIP-712 signing helpers, and verifier source extracted from Armoreum.

[MIT License](LICENSE) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Releases](https://github.com/armoreum/armoreum-authorization/releases) · [Support](mailto:support@armoreum.io)

## Status

**Source preview extracted from actual supplied code.** This is a focused module repository, not an additional original package found in the archives. The application and full contract snapshots are preserved separately. No live service, deployment, independent audit, or registry package is claimed.

## Source modules

- `src/authorization.ts`
- `src/creator-authorization.ts`
- `src/creator-password-authorization.ts`
- `src/eip712-wallet-signing.ts`

The repository includes **3 Solidity files**, including the complete relative-import closure of the selected module. Compile with `npm run compile` after reviewing dependencies. Full Solidity compilation/integration tests are not claimed by this source extraction.

## Authorization families

The source includes separate authorization families; they are not interchangeable:

- `authorization.ts`: legacy domain-separated authorization, 64 epochs and 256 proofs per chain.
- `creator-authorization.ts`: creator/PRF-based material, 64 epochs and 256 proofs per chain.
- `creator-password-authorization.ts`: password v2 protocol, Argon2id, 64 epochs and 100 proofs per operation chain.
- `eip712-wallet-signing.ts`: typed-data wallet signing and signature verification.

Each family retains its original domain constants. Changing domains, epoch limits, counters, or proof order can invalidate existing commitments.

The password flow calls a server seed endpoint. The actual seed server is not included; tests use synthetic inputs or mocks. ECDSA remains conventional cryptography. Hash preimages provide a narrow additional authorization mechanism, not universal post-quantum protection.

## Development and verification

Use Node.js 24 or newer and review dependencies before installation:

```sh
npm install --ignore-scripts
npm test
```

The source archive had no original dependency lockfile. Dependency versions for this module are explicit, but complete transitive resolution and audit must still be reviewed. For source inspection, the copied Node tests can also be run directly after installing their runtime dependencies in an isolated environment.

See [verification](docs/verification.md) for checks actually performed. Tests use synthetic data; no funded transaction or mainnet write is part of this verification.

## Provenance and shared code

[SOURCE_MANIFEST.json](SOURCE_MANIFEST.json) records each copied source path and checksum. Read [source scope](docs/source-scope.md). Shared code is deliberately preserved when necessary; the repository count does not imply seven independent implementations or seven running services.

## Open source and releases

Project-owned source is MIT-licensed; upstream imports retain their own licenses. GitHub Releases provide tagged source ZIP/TAR archives. `private: true` prevents accidental npm publication; it does not restrict the public source. Do not treat the source preview as an audited deployable package.

## Armoreum ecosystem

[armoreum](https://github.com/armoreum/armoreum) · [armoreum-contracts](https://github.com/armoreum/armoreum-contracts) · [armoreum-authorization](https://github.com/armoreum/armoreum-authorization) · [armoreum-recovery](https://github.com/armoreum/armoreum-recovery) · [armoreum-bridge](https://github.com/armoreum/armoreum-bridge) · [armoreum-launchpad](https://github.com/armoreum/armoreum-launchpad) · [armoreum-docs](https://github.com/armoreum/armoreum-docs)

Issues and pull requests are open. General and private security contact: **support@armoreum.io**.

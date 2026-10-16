import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, recoverAddress, toUtf8Bytes } from "ethers";
import {
  derivePasswordAuthorizationSigner,
  deriveCreatorPasswordKdf,
  derivePasswordAuthorizationMaterial,
  derivePasswordAuthorizationProofChains,
  derivePasswordAuthorizationProof,
  CreatorWalletMismatchError,
  PASSWORD_AUTH_KDF,
  requestCreatorAuthorizationSeed,
  signPasswordAuthorizationDigest,
  validateCreatorAuthorizationPassword,
  verifyPasswordAuthorizationProof,
} from "./creator-password-authorization.ts";

const context = {
  chainId: 4663,
  vaultAddress: `0x${"11".repeat(20)}`,
  creatorAddress: `0x${"22".repeat(20)}`,
  launchId: `0x${"33".repeat(32)}`,
};
const seed = new Uint8Array(32).fill(0x5a);

test("creator wallet conflicts are surfaced as a recoverable draft mismatch", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    code: "CREATOR_WALLET_MISMATCH",
    error: "This saved draft belongs to a different creator wallet.",
  }), { status: 409 });
  try {
    await assert.rejects(
      requestCreatorAuthorizationSeed("00000000-0000-4000-8000-000000000000", new Uint8Array(32)),
      CreatorWalletMismatchError,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("password rules preserve six characters and accept long letter-number passwords", () => {
  assert.doesNotThrow(() => validateCreatorAuthorizationPassword("Ab1234"));
  assert.doesNotThrow(() => validateCreatorAuthorizationPassword(`A1${"x".repeat(20_000)}`));
  assert.throws(() => validateCreatorAuthorizationPassword("A1234"), /at least 6/i);
  assert.throws(() => validateCreatorAuthorizationPassword("letters-only"), /letters and numbers/i);
  assert.throws(() => validateCreatorAuthorizationPassword("123456"), /letters and numbers/i);
});

test("password KDF uses Argon2id and produces a 32-byte value", async () => {
  const derived = await deriveCreatorPasswordKdf("Ab1234", context.launchId);
  assert.equal(derived.length, 32);
  assert.equal(PASSWORD_AUTH_KDF.algorithm, "Argon2id");
  assert.equal(PASSWORD_AUTH_KDF.memorySizeKiB, 65_536);
  assert.equal(PASSWORD_AUTH_KDF.iterations, 3);
});

test("one-time chain proofs descend H99 to H0 and verify against the prior anchor", async () => {
  const h99 = await derivePasswordAuthorizationProof(seed, context, "claim", 1, 100);
  const h98 = await derivePasswordAuthorizationProof(seed, context, "claim", 1, 99);
  assert.equal(await verifyPasswordAuthorizationProof(h99, await sha256Hex(h99)), true);
  assert.equal(await verifyPasswordAuthorizationProof(h98, h99), true);
  assert.notEqual(h99, h98);
  await assert.rejects(
    derivePasswordAuthorizationProof(seed, context, "claim", 1, 0),
    /no unused/i,
  );
});

test("post-launch offline H100-H0 chains reproduce the authorization root committed by the launch", async () => {
  const material = await derivePasswordAuthorizationMaterial(seed, context);
  const derived = await derivePasswordAuthorizationProofChains(seed, context);
  assert.equal(derived.chains.length, 4 * 64);
  assert.equal(derived.authorizationEpochRoot, material.authorizationEpochRoot);
  const initialClaimChain = derived.chains.find(({ operation, epoch }) => operation === "claim" && epoch === 1);
  assert.equal(initialClaimChain.h100, material.claimCommitment);
  assert.equal(initialClaimChain.h99ToH0.length, 100);
});

test("proofs are separated by chain, vault, launch, operation, and epoch", async () => {
  const base = await derivePasswordAuthorizationProof(seed, context, "claim", 1, 100);
  const otherChain = await derivePasswordAuthorizationProof(seed, { ...context, chainId: 1 }, "claim", 1, 100);
  const otherOperation = await derivePasswordAuthorizationProof(seed, context, "redemption", 1, 100);
  const otherEpoch = await derivePasswordAuthorizationProof(seed, context, "claim", 2, 100);
  assert.notEqual(base, otherChain);
  assert.notEqual(base, otherOperation);
  assert.notEqual(base, otherEpoch);
});

test("password-derived signer signatures bind action digests without exposing the private key", async () => {
  const signer = await derivePasswordAuthorizationSigner(seed, context);
  const digest = keccak256(toUtf8Bytes("protected recipient and amount"));
  const signature = await signPasswordAuthorizationDigest(seed, context, digest);
  assert.equal(recoverAddress(digest, signature), signer);
  assert.equal(signature.length, 132);
});

async function sha256Hex(hex) {
  const bytes = Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
  return `0x${Buffer.from(await globalThis.crypto.subtle.digest("SHA-256", bytes)).toString("hex")}`;
}

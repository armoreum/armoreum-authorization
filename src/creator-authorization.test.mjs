import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";

globalThis.crypto ??= webcrypto;

const {
  creatorAuthorizationPrfInput,
  deriveCreatorAuthorizationMaterial,
  deriveCreatorAuthorizationProof,
  verifyCreatorAuthorizationProof,
} = await import("./creator-authorization.ts");

test("authorization material is deterministic and yields a valid initial claim proof", async () => {
  const prfOutput = new Uint8Array(32).fill(7);
  const context = {
    chainId: 4663,
    vaultAddress: "0x1111111111111111111111111111111111111111",
    creatorAddress: "0x2222222222222222222222222222222222222222",
    launchId: `0x${"ab".repeat(32)}`,
  };

  assert.ok(creatorAuthorizationPrfInput().length > 0);
  const progress = [];
  const first = await deriveCreatorAuthorizationMaterial(prfOutput, context, (done) => {
    progress.push(done);
  });
  const second = await deriveCreatorAuthorizationMaterial(prfOutput, context);

  assert.equal(first.authorizationEpochRoot, second.authorizationEpochRoot);
  assert.equal(first.claimCommitment, second.claimCommitment);
  assert.equal(first.initialEpochProof.length, 6);
  assert.deepEqual(progress, Array.from({ length: 64 }, (_, index) => index + 1));

  const proof = await deriveCreatorAuthorizationProof(prfOutput, context, "claim", 1, 256);
  assert.equal(await verifyCreatorAuthorizationProof(proof, first.claimCommitment), true);
  assert.equal(await verifyCreatorAuthorizationProof(proof, first.redemptionCommitment), false);
});

test("authorization proof rejects invalid epochs and exhausted chains", async () => {
  const prfOutput = new Uint8Array(32).fill(9);
  const context = {
    chainId: 4663,
    vaultAddress: "0x1111111111111111111111111111111111111111",
    creatorAddress: "0x2222222222222222222222222222222222222222",
    launchId: `0x${"cd".repeat(32)}`,
  };

  await assert.rejects(
    deriveCreatorAuthorizationProof(prfOutput, context, "claim", 65, 256),
    /outside the supported range/,
  );
  await assert.rejects(
    deriveCreatorAuthorizationProof(prfOutput, context, "claim", 1, 0),
    /No authorization proofs remain in this epoch/,
  );
});

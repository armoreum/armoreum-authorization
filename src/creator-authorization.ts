const AUTHORIZATION_DOMAIN = "armoreum.creator.authorization.v1";
const PRF_INPUT_DOMAIN = "armoreum.creator.authorization.prf.v1";
const EPOCH_LEAF_DOMAIN =
  "0xe20e3cf5c060538b219cbc5443726159f6f4ba6949556cde43f0425a795d692e";
const PROOFS_PER_EPOCH = 256;
const AUTHORIZATION_EPOCHS = 64;
const OPERATIONS = ["claim", "redemption", "rotation", "recovery"] as const;

export type AuthorizationOperation = (typeof OPERATIONS)[number];

export interface CreatorAuthorizationContext {
  chainId: number;
  vaultAddress: string;
  creatorAddress: string;
  launchId: string;
}

export interface CreatorAuthorizationMaterial {
  authorizationEpochRoot: string;
  claimCommitment: string;
  redemptionCommitment: string;
  rotationCommitment: string;
  recoveryCommitment: string;
  initialEpochProof: string[];
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(value.length);
  new Uint8Array(buffer).set(value);
  return buffer;
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function toHex(value: Uint8Array): string {
  return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function fromHex(value: string, expectedBytes?: number): Uint8Array {
  if (!/^0x(?:[\da-f]{2})+$/i.test(value)) {
    throw new Error("Authorization data must be even-length hexadecimal bytes.");
  }
  const bytes = new Uint8Array((value.length - 2) / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new Error(`Expected ${expectedBytes} bytes of authorization data.`);
  }
  return bytes;
}

function uintBytes(value: bigint, width: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(width * 8)) {
    throw new Error("Authorization context contains an out-of-range integer.");
  }
  const bytes = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function addressBytes(address: string): Uint8Array {
  if (!/^0x[\da-f]{40}$/i.test(address)) {
    throw new Error("Authorization context contains an invalid EVM address.");
  }
  return fromHex(address, 20);
}

function validateContext(context: CreatorAuthorizationContext): {
  chainIdBytes: Uint8Array;
  vaultBytes: Uint8Array;
  creatorBytes: Uint8Array;
  launchIdBytes: Uint8Array;
} {
  if (!Number.isSafeInteger(context.chainId) || context.chainId <= 0) {
    throw new Error("Authorization context contains an invalid chain ID.");
  }
  return {
    chainIdBytes: uintBytes(BigInt(context.chainId), 32),
    vaultBytes: addressBytes(context.vaultAddress),
    creatorBytes: addressBytes(context.creatorAddress),
    launchIdBytes: fromHex(context.launchId, 32),
  };
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", arrayBuffer(value)));
}

async function createPrfKey(prfOutput: Uint8Array): Promise<CryptoKey> {
  if (prfOutput.length !== 32) {
    throw new Error("The authorization credential did not return the 32-byte PRF output required for this operation.");
  }
  return globalThis.crypto.subtle.importKey(
    "raw",
    arrayBuffer(prfOutput),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

export function creatorAuthorizationPrfInput(): Uint8Array {
  return utf8(PRF_INPUT_DOMAIN);
}

async function deriveChainSeed(
  key: CryptoKey,
  context: CreatorAuthorizationContext,
  operation: AuthorizationOperation,
  epoch: number,
): Promise<Uint8Array> {
  const encoded = validateContext(context);
  const operationIndex = OPERATIONS.indexOf(operation);
  if (operationIndex < 0 || !Number.isInteger(epoch) || epoch < 1 || epoch > AUTHORIZATION_EPOCHS) {
    throw new Error("Authorization operation or epoch is outside the supported range.");
  }
  const info = concatBytes(
    utf8(`${AUTHORIZATION_DOMAIN}:hash-chain:`),
    encoded.chainIdBytes,
    encoded.vaultBytes,
    encoded.creatorBytes,
    encoded.launchIdBytes,
    uintBytes(BigInt(epoch), 4),
    uintBytes(BigInt(operationIndex), 1),
  );
  return new Uint8Array(
    await globalThis.crypto.subtle.sign("HMAC", key, arrayBuffer(info)),
  );
}

async function chainCommitment(seed: Uint8Array): Promise<Uint8Array> {
  let current = seed;
  for (let index = 0; index < PROOFS_PER_EPOCH; index += 1) {
    current = await sha256(current);
  }
  return current;
}

async function epochLeaf(
  context: CreatorAuthorizationContext,
  epoch: number,
  commitments: Uint8Array[],
): Promise<Uint8Array> {
  const encoded = validateContext(context);
  const leafInput = concatBytes(
    fromHex(EPOCH_LEAF_DOMAIN, 32),
    encoded.chainIdBytes,
    encoded.vaultBytes,
    encoded.creatorBytes,
    encoded.launchIdBytes,
    uintBytes(BigInt(epoch), 4),
    ...commitments,
  );
  return sha256(leafInput);
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

async function parentHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(compareBytes(left, right) < 0 ? concatBytes(left, right) : concatBytes(right, left));
}

async function buildEpochTree(
  leaves: Uint8Array[],
): Promise<{ root: Uint8Array; proof: Uint8Array[] }> {
  if (leaves.length !== AUTHORIZATION_EPOCHS) {
    throw new Error("Authorization tree must contain exactly 64 epoch leaves.");
  }
  const layers = [leaves];
  while (layers[layers.length - 1].length > 1) {
    const current = layers[layers.length - 1];
    const next: Uint8Array[] = [];
    for (let index = 0; index < current.length; index += 2) {
      next.push(await parentHash(current[index], current[index + 1]));
    }
    layers.push(next);
  }

  const proof: Uint8Array[] = [];
  let position = 0;
  for (const layer of layers.slice(0, -1)) {
    proof.push(layer[position ^ 1]);
    position = Math.floor(position / 2);
  }
  if (proof.length !== 6) {
    throw new Error("Authorization epoch proof has the wrong depth.");
  }
  return { root: layers[layers.length - 1][0], proof };
}

export async function deriveCreatorAuthorizationMaterial(
  prfOutput: Uint8Array,
  context: CreatorAuthorizationContext,
  onEpochProgress?: (completed: number, total: number) => void,
): Promise<CreatorAuthorizationMaterial> {
  validateContext(context);
  const key = await createPrfKey(prfOutput);
  const leaves: Uint8Array[] = [];
  let initialCommitments: Uint8Array[] | undefined;

  for (let epoch = 1; epoch <= AUTHORIZATION_EPOCHS; epoch += 1) {
    const commitments = await Promise.all(
      OPERATIONS.map(async (operation) =>
        chainCommitment(await deriveChainSeed(key, context, operation, epoch)),
      ),
    );
    if (epoch === 1) initialCommitments = commitments;
    leaves.push(await epochLeaf(context, epoch, commitments));
    onEpochProgress?.(epoch, AUTHORIZATION_EPOCHS);
  }

  if (!initialCommitments) throw new Error("Initial authorization commitments were not derived.");
  const { root, proof } = await buildEpochTree(leaves);
  return {
    authorizationEpochRoot: toHex(root),
    claimCommitment: toHex(initialCommitments[0]),
    redemptionCommitment: toHex(initialCommitments[1]),
    rotationCommitment: toHex(initialCommitments[2]),
    recoveryCommitment: toHex(initialCommitments[3]),
    initialEpochProof: proof.map(toHex),
  };
}

export async function deriveCreatorAuthorizationProof(
  prfOutput: Uint8Array,
  context: CreatorAuthorizationContext,
  operation: AuthorizationOperation,
  epoch: number,
  proofsRemaining: number,
): Promise<string> {
  if (
    !Number.isInteger(proofsRemaining)
    || proofsRemaining < 1
    || proofsRemaining > PROOFS_PER_EPOCH
  ) {
    throw new Error("No authorization proofs remain in this epoch.");
  }
  const key = await createPrfKey(prfOutput);
  let proof = await deriveChainSeed(key, context, operation, epoch);
  for (let index = 1; index < proofsRemaining; index += 1) {
    proof = await sha256(proof);
  }
  return toHex(proof);
}

export async function verifyCreatorAuthorizationProof(
  proof: string,
  commitment: string,
): Promise<boolean> {
  return toHex(await sha256(fromHex(proof, 32))).toLowerCase() === commitment.toLowerCase();
}

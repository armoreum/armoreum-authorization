import { argon2id } from "hash-wasm";
import { Wallet } from "ethers";
export const PASSWORD_AUTHORIZATION_PROTOCOL = "armoreum.creator.password.authorization.v2";
export const PASSWORD_PROOFS_PER_EPOCH = 100;
export const PASSWORD_AUTHORIZATION_EPOCHS = 64;
export const PASSWORD_AUTH_KDF = {
  algorithm: "Argon2id",
  memorySizeKiB: 65_536,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
} as const;

const OPERATIONS = ["claim", "redemption", "rotation", "recovery"] as const;
export type PasswordAuthorizationOperation = (typeof OPERATIONS)[number];
const EPOCH_LEAF_DOMAIN = "0xe20e3cf5c060538b219cbc5443726159f6f4ba6949556cde43f0425a795d692e";
const SERVER_SEED_ROUTE = "creator-auth-seed";
const SIGNER_DOMAIN = "armoreum.creator.password.authorization.v2:secp256k1:";
const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export class CreatorWalletMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CreatorWalletMismatchError";
  }
}

export interface PasswordAuthorizationContext {
  chainId: number;
  vaultAddress: string;
  creatorAddress: string;
  launchId: string;
}

export interface PasswordAuthorizationMaterial {
  authorizationSigner: string;
  authorizationEpochRoot: string;
  claimCommitment: string;
  redemptionCommitment: string;
  rotationCommitment: string;
  recoveryCommitment: string;
  initialEpochProof: string[];
}

export interface PasswordAuthorizationProofChain {
  operation: PasswordAuthorizationOperation;
  epoch: number;
  h100: string;
  h99ToH0: string[];
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  const output = new ArrayBuffer(value.length);
  new Uint8Array(output).set(value);
  return output;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function toHex(value: Uint8Array): string {
  return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function fromHex(value: string, expectedBytes: number): Uint8Array {
  if (!new RegExp(`^0x[\\da-f]{${expectedBytes * 2}}$`, "i").test(value)) {
    throw new Error("Password authorization context is malformed.");
  }
  const output = new Uint8Array(expectedBytes);
  for (let index = 0; index < expectedBytes; index += 1) {
    output[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return output;
}

function uintBytes(value: bigint, width: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(width * 8)) throw new Error("Authorization integer is out of range.");
  const output = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    output[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return output;
}

function addressBytes(value: string): Uint8Array {
  return fromHex(value, 20);
}

function validateContext(context: PasswordAuthorizationContext) {
  if (!Number.isSafeInteger(context.chainId) || context.chainId < 1) {
    throw new Error("Authorization context has an invalid chain ID.");
  }
  return {
    chain: uintBytes(BigInt(context.chainId), 32),
    vault: addressBytes(context.vaultAddress),
    creator: addressBytes(context.creatorAddress),
    launchId: fromHex(context.launchId, 32),
  };
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", asArrayBuffer(value)));
}

async function keyedHash(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    asArrayBuffer(seed),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, asArrayBuffer(message)));
}

export function validateCreatorAuthorizationPassword(password: string): void {
  const normalized = password.normalize("NFKC");
  if (Array.from(normalized).length < 6) throw new Error("Use at least 6 characters.");
  if (!/\p{L}/u.test(normalized) || !/\p{N}/u.test(normalized)) {
    throw new Error("Use a combination of letters and numbers.");
  }
}

export async function deriveCreatorPasswordKdf(password: string, launchId: string): Promise<Uint8Array> {
  validateCreatorAuthorizationPassword(password);
  const salt = fromHex(launchId, 32);
  return argon2id({
    password: password.normalize("NFKC"),
    salt,
    parallelism: PASSWORD_AUTH_KDF.parallelism,
    iterations: PASSWORD_AUTH_KDF.iterations,
    memorySize: PASSWORD_AUTH_KDF.memorySizeKiB,
    hashLength: PASSWORD_AUTH_KDF.hashLength,
    outputType: "binary",
  });
}

export async function requestCreatorAuthorizationSeed(
  draftId: string,
  passwordKdf: Uint8Array,
): Promise<{
  seed: Uint8Array;
  creatorPrivateKey: string;
  launchId: string;
  creatorAddress: string;
  serverKeyId: string;
}> {
  if (passwordKdf.length !== PASSWORD_AUTH_KDF.hashLength) {
    throw new Error("Password-derived input has an invalid length.");
  }
  const response = await fetch(
    `/api/launch-drafts/${encodeURIComponent(draftId)}/${SERVER_SEED_ROUTE}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      body: JSON.stringify({ passwordKdf: toHex(passwordKdf) }),
    },
  );
  const result = (await response.json()) as {
    code?: string;
    error?: string;
    seed?: string;
    creatorPrivateKey?: string;
    launchId?: string;
    creatorAddress?: string;
    serverKeyId?: string;
  };
  if (response.status === 409 && result.code === "CREATOR_WALLET_MISMATCH") {
    throw new CreatorWalletMismatchError(
      result.error || "This saved draft belongs to a different creator wallet.",
    );
  }
  if (!response.ok || !result.seed || !result.creatorPrivateKey || !result.launchId || !result.creatorAddress || !result.serverKeyId) {
    throw new Error(result.error || "Creator authorization could not be prepared.");
  }
  return {
    seed: fromHex(result.seed, 32),
    creatorPrivateKey: result.creatorPrivateKey,
    launchId: result.launchId,
    creatorAddress: result.creatorAddress,
    serverKeyId: result.serverKeyId,
  };
}

async function chainSeed(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
  operation: PasswordAuthorizationOperation,
  epoch: number,
): Promise<Uint8Array> {
  const encoded = validateContext(context);
  if (!OPERATIONS.includes(operation) || !Number.isInteger(epoch) || epoch < 1 || epoch > PASSWORD_AUTHORIZATION_EPOCHS) {
    throw new Error("Authorization operation or epoch is invalid.");
  }
  return keyedHash(seed, concatBytes(
    utf8(`${PASSWORD_AUTHORIZATION_PROTOCOL}:chain:`),
    encoded.chain,
    encoded.vault,
    encoded.creator,
    encoded.launchId,
    utf8(operation),
    uintBytes(BigInt(epoch), 4),
  ));
}

async function passwordSignerPrivateKey(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
): Promise<string> {
  if (seed.length !== 32) throw new Error("Authorization seed must be 32 bytes.");
  const encoded = validateContext(context);
  for (let counter = 0; counter < 256; counter += 1) {
    const candidate = await keyedHash(
      seed,
      concatBytes(
        utf8(SIGNER_DOMAIN),
        encoded.chain,
        encoded.creator,
        encoded.launchId,
        uintBytes(BigInt(counter), 4),
      ),
    );
    const scalar = BigInt(toHex(candidate));
    if (scalar > 0n && scalar < SECP256K1_ORDER) return toHex(candidate);
  }
  throw new Error("Password authorization key derivation failed.");
}

export async function derivePasswordAuthorizationSigner(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
): Promise<string> {
  return new Wallet(await passwordSignerPrivateKey(seed, context)).address;
}

export async function signPasswordAuthorizationDigest(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
  digest: string,
): Promise<string> {
  fromHex(digest, 32);
  const wallet = new Wallet(await passwordSignerPrivateKey(seed, context));
  return wallet.signingKey.sign(digest).serialized;
}

async function commitment(seed: Uint8Array): Promise<Uint8Array> {
  let value = seed;
  for (let index = 0; index < PASSWORD_PROOFS_PER_EPOCH; index += 1) value = await sha256(value);
  return value;
}

async function epochLeaf(
  context: PasswordAuthorizationContext,
  epoch: number,
  commitments: Uint8Array[],
): Promise<Uint8Array> {
  const encoded = validateContext(context);
  return sha256(concatBytes(
    fromHex(EPOCH_LEAF_DOMAIN, 32),
    encoded.chain,
    encoded.vault,
    encoded.creator,
    encoded.launchId,
    uintBytes(BigInt(epoch), 4),
    ...commitments,
  ));
}

async function buildMerkleTree(leaves: Uint8Array[]) {
  const layers = [leaves];
  while (layers[layers.length - 1].length > 1) {
    const previous = layers[layers.length - 1];
    const next: Uint8Array[] = [];
    for (let index = 0; index < previous.length; index += 2) {
      const [left, right] = compareBytes(previous[index], previous[index + 1]) < 0
        ? [previous[index], previous[index + 1]]
        : [previous[index + 1], previous[index]];
      next.push(await sha256(concatBytes(left, right)));
    }
    layers.push(next);
  }
  const proof: Uint8Array[] = [];
  let index = 0;
  for (let level = 0; level < layers.length - 1; level += 1) {
    proof.push(layers[level][index ^ 1]);
    index = Math.floor(index / 2);
  }
  return { root: layers[layers.length - 1][0], proof };
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

export async function derivePasswordAuthorizationMaterial(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
  onEpochProgress?: (completed: number, total: number) => void,
): Promise<PasswordAuthorizationMaterial> {
  if (seed.length !== 32) throw new Error("Authorization seed must be 32 bytes.");
  const authorizationSigner = await derivePasswordAuthorizationSigner(seed, context);
  const leaves: Uint8Array[] = [];
  let initialCommitments: Uint8Array[] | undefined;
  for (let epoch = 1; epoch <= PASSWORD_AUTHORIZATION_EPOCHS; epoch += 1) {
    const current = await Promise.all(OPERATIONS.map(async (operation) =>
      commitment(await chainSeed(seed, context, operation, epoch)),
    ));
    if (epoch === 1) initialCommitments = current;
    leaves.push(await epochLeaf(context, epoch, current));
    onEpochProgress?.(epoch, PASSWORD_AUTHORIZATION_EPOCHS);
  }
  if (!initialCommitments) throw new Error("Initial password authorization commitments are missing.");
  const tree = await buildMerkleTree(leaves);
  return {
    authorizationSigner,
    authorizationEpochRoot: toHex(tree.root),
    claimCommitment: toHex(initialCommitments[0]),
    redemptionCommitment: toHex(initialCommitments[1]),
    rotationCommitment: toHex(initialCommitments[2]),
    recoveryCommitment: toHex(initialCommitments[3]),
    initialEpochProof: tree.proof.map(toHex),
  };
}

export async function derivePasswordAuthorizationProof(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
  operation: PasswordAuthorizationOperation,
  epoch: number,
  proofsRemaining: number,
): Promise<string> {
  if (!Number.isInteger(proofsRemaining) || proofsRemaining < 1 || proofsRemaining > PASSWORD_PROOFS_PER_EPOCH) {
    throw new Error("No unused password authorization proofs remain in this epoch.");
  }
  let proof = await chainSeed(seed, context, operation, epoch);
  for (let index = 1; index < proofsRemaining; index += 1) proof = await sha256(proof);
  return toHex(proof);
}

export async function derivePasswordAuthorizationProofChain(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
  operation: PasswordAuthorizationOperation,
  epoch: number,
): Promise<PasswordAuthorizationProofChain> {
  if (seed.length !== 32) throw new Error("Authorization seed must be 32 bytes.");
  if (!OPERATIONS.includes(operation) || !Number.isInteger(epoch) || epoch < 1 || epoch > PASSWORD_AUTHORIZATION_EPOCHS) {
    throw new Error("Authorization operation or epoch is invalid.");
  }
  let value = await chainSeed(seed, context, operation, epoch);
  const h0ToH99: string[] = [];
  for (let index = 0; index < PASSWORD_PROOFS_PER_EPOCH; index += 1) {
    h0ToH99.push(toHex(value));
    const next = await sha256(value);
    value.fill(0);
    value = next;
  }
  const chain = {
    operation,
    epoch,
    h100: toHex(value),
    h99ToH0: h0ToH99.reverse(),
  };
  value.fill(0);
  return chain;
}

export async function derivePasswordAuthorizationProofChains(
  seed: Uint8Array,
  context: PasswordAuthorizationContext,
  onProgress?: (completed: number, total: number) => void,
  signal?: AbortSignal,
): Promise<{ chains: PasswordAuthorizationProofChain[]; authorizationEpochRoot: string }> {
  const total = OPERATIONS.length * PASSWORD_AUTHORIZATION_EPOCHS;
  const chains: PasswordAuthorizationProofChain[] = [];
  let completed = 0;

  for (let epoch = 1; epoch <= PASSWORD_AUTHORIZATION_EPOCHS; epoch += 1) {
    for (const operation of OPERATIONS) {
      if (signal?.aborted) throw new Error("Recovery capsule preparation was cancelled.");
      chains.push(await derivePasswordAuthorizationProofChain(seed, context, operation, epoch));
      completed += 1;
      onProgress?.(completed, total);
    }
  }
  const leaves: Uint8Array[] = [];
  for (let epoch = 1; epoch <= PASSWORD_AUTHORIZATION_EPOCHS; epoch += 1) {
    if (signal?.aborted) throw new Error("Recovery capsule preparation was cancelled.");
    const commitments = OPERATIONS.map((operation) => {
      const chain = chains.find((candidate) => candidate.operation === operation && candidate.epoch === epoch);
      if (!chain) throw new Error("A recovery hash chain could not be prepared.");
      return fromHex(chain.h100, 32);
    });
    leaves.push(await epochLeaf(context, epoch, commitments));
  }
  const tree = await buildMerkleTree(leaves);
  return { chains, authorizationEpochRoot: toHex(tree.root) };
}

export async function verifyPasswordAuthorizationProof(proof: string, anchor: string): Promise<boolean> {
  return toHex(await sha256(fromHex(proof, 32))).toLowerCase() === anchor.toLowerCase();
}

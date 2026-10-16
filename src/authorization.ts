export const AUTHORIZATION_VERSION = 1;
export const AUTHORIZATION_EPOCH_COUNT = 64;
export const AUTHORIZATION_PROOFS_PER_EPOCH = 256;
export const AUTHORIZATION_ROTATION_THRESHOLD = 32;

const encoder = new TextEncoder();
// Keep the established v1 proof domain byte-for-byte stable across product rebrands.
const DOMAIN_PREFIX = hexBytes(
  '0x42756c6c657470726f6f662f496e646570656e64656e74417574686f72697a6174696f6e2f7631',
  39,
  'Authorization domain',
);
const PURPOSES = ['claim', 'redemption', 'rotation', 'recovery'] as const;

export type AuthorizationPurpose = (typeof PURPOSES)[number];

export type AuthorizationContext = {
  chainId: bigint | number | string;
  vaultAddress: string;
  creatorAddress: string;
  launchId: string;
};

export type EpochCommitments = Record<AuthorizationPurpose, string>;

export type AuthorizationTree = {
  root: string;
  epochs: Array<{
    epoch: number;
    commitments: EpochCommitments;
    merkleProof: string[];
  }>;
};

export type DerivationProgress = (progress: number, stage: 'derivation' | 'tree') => void;

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function hexBytes(value: string, byteLength: number, label: string): Uint8Array {
  if (!new RegExp(`^0x[\\da-fA-F]{${byteLength * 2}}$`).test(value)) {
    throw new Error(`${label} must be a ${byteLength}-byte hex value.`);
  }
  return Uint8Array.from(value.slice(2).match(/.{2}/g) || [], (byte) => Number.parseInt(byte, 16));
}

function uintBytes(value: bigint | number | string, length = 32): Uint8Array {
  let number = BigInt(value);
  if (number < 0n || number >= (1n << BigInt(length * 8))) throw new Error('Chain ID is out of range.');
  const bytes = new Uint8Array(length);
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(number & 0xffn);
    number >>= 8n;
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function sha256(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', asArrayBuffer(input)));
}

function contextBytes(context: AuthorizationContext): Uint8Array {
  return concatBytes(
    uintBytes(context.chainId),
    hexBytes(context.vaultAddress, 20, 'Vault address'),
    hexBytes(context.creatorAddress, 20, 'Creator address'),
    hexBytes(context.launchId, 32, 'Launch ID'),
  );
}

async function requestPasskeyPrfOutput(
  context: AuthorizationContext,
  credentialId?: Uint8Array,
): Promise<Uint8Array> {
  if (typeof navigator === 'undefined' || !navigator.credentials?.get) {
    throw new Error('Creator authorization is unavailable in this browser.');
  }
  if (!globalThis.isSecureContext) {
    throw new Error('Creator authorization requires a secure connection.');
  }
  if (credentialId && credentialId.length === 0) {
    throw new Error('The selected authorization credential is invalid.');
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const prfInput = await sha256(
    concatBytes(
      DOMAIN_PREFIX,
      encoder.encode('/passkey-prf-input/'),
      contextBytes(context),
    ),
  );
  const publicKey = {
    challenge: asArrayBuffer(challenge),
    timeout: 60_000,
    userVerification: 'required',
    ...(credentialId
      ? {
          allowCredentials: [
            {
              type: 'public-key',
              id: asArrayBuffer(credentialId),
            },
          ],
        }
      : {}),
    extensions: {
      prf: {
        eval: {
          first: asArrayBuffer(prfInput),
        },
      },
    },
  };
  const assertion = await navigator.credentials.get({
    publicKey,
  } as unknown as CredentialRequestOptions);
  if (
    !assertion
      || typeof (assertion as PublicKeyCredential).getClientExtensionResults
        !== 'function'
  ) {
    throw new Error('Creator authorization was cancelled or not completed.');
  }

  const publicKeyAssertion = assertion as PublicKeyCredential;
  const extensionResults = publicKeyAssertion.getClientExtensionResults() as unknown as {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const output = extensionResults.prf?.results?.first;
  if (!(output instanceof ArrayBuffer) || output.byteLength !== 32) {
    throw new Error(
      'This authenticator does not support secure PRF derivation; use a compatible authorization credential.',
    );
  }
  const copiedOutput = new Uint8Array(output.slice(0));
  new Uint8Array(output).fill(0);
  return copiedOutput;
}

async function deriveMaster(
  passkeyPrfOutput: Uint8Array,
  context: AuthorizationContext,
  onProgress?: DerivationProgress,
): Promise<Uint8Array> {
  if (passkeyPrfOutput.byteLength !== 32) {
    throw new Error('Authenticator PRF output must be 32 bytes.');
  }
  const salt = await sha256(
    concatBytes(
      DOMAIN_PREFIX,
      encoder.encode('/hkdf-salt/'),
      contextBytes(context),
    ),
  );
  const baseKey = await crypto.subtle.importKey(
    'raw',
    asArrayBuffer(passkeyPrfOutput),
    'HKDF',
    false,
    ['deriveBits'],
  );
  const master = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: asArrayBuffer(salt),
        info: asArrayBuffer(
          concatBytes(
            DOMAIN_PREFIX,
            encoder.encode('/master/passkey-prf/'),
          ),
        ),
      },
      baseKey,
      256,
    ),
  );
  onProgress?.(1, 'derivation');
  return master;
}

async function derivePurposeSeed(
  master: Uint8Array,
  context: AuthorizationContext,
  epoch: number,
  purpose: AuthorizationPurpose,
): Promise<Uint8Array> {
  const contextSalt = await sha256(concatBytes(DOMAIN_PREFIX, encoder.encode('/hkdf-salt/'), contextBytes(context)));
  const baseKey = await crypto.subtle.importKey('raw', asArrayBuffer(master), 'HKDF', false, ['deriveBits']);
  const info = concatBytes(
    DOMAIN_PREFIX,
    encoder.encode(`/${purpose}/`),
    uintBytes(epoch, 4),
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: asArrayBuffer(contextSalt),
      info: asArrayBuffer(info),
    },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

async function commitmentForSeed(seed: Uint8Array): Promise<string> {
  let current = seed;
  for (let step = 0; step < AUTHORIZATION_PROOFS_PER_EPOCH; step += 1) {
    current = await sha256(current);
  }
  return toHex(current);
}

async function epochLeaf(context: AuthorizationContext, epoch: number, commitments: EpochCommitments) {
  const domain = await sha256(concatBytes(DOMAIN_PREFIX, encoder.encode('/epoch-leaf/')));
  return sha256(concatBytes(
    domain,
    contextBytes(context),
    uintBytes(epoch, 4),
    ...PURPOSES.map((purpose) => hexBytes(commitments[purpose], 32, `${purpose} commitment`)),
  ));
}

async function merkleParent(left: Uint8Array, right: Uint8Array) {
  const leftHex = toHex(left).toLowerCase();
  const rightHex = toHex(right).toLowerCase();
  return sha256(leftHex < rightHex ? concatBytes(left, right) : concatBytes(right, left));
}

export async function deriveAuthorizationTree(
  context: AuthorizationContext,
  credentialId?: Uint8Array,
  onProgress?: DerivationProgress,
): Promise<AuthorizationTree> {
  const passkeyPrfOutput = await requestPasskeyPrfOutput(context, credentialId);
  let master: Uint8Array | undefined;
  try {
    master = await deriveMaster(passkeyPrfOutput, context, onProgress);
    const epochs: AuthorizationTree['epochs'] = [];
    const leaves: Uint8Array[] = [];
    const workTotal = AUTHORIZATION_EPOCH_COUNT * PURPOSES.length;
    let workDone = 0;

    for (let epoch = 1; epoch <= AUTHORIZATION_EPOCH_COUNT; epoch += 1) {
      const commitments = {} as EpochCommitments;
      for (const purpose of PURPOSES) {
        const seed = await derivePurposeSeed(master, context, epoch, purpose);
        commitments[purpose] = await commitmentForSeed(seed);
        seed.fill(0);
        workDone += 1;
        onProgress?.(workDone / workTotal, 'tree');
      }
      epochs.push({ epoch, commitments, merkleProof: [] });
      leaves.push(await epochLeaf(context, epoch, commitments));
    }

    const layers: Uint8Array[][] = [leaves];
    while (layers.at(-1)!.length > 1) {
      const current = layers.at(-1)!;
      const next: Uint8Array[] = [];
      for (let index = 0; index < current.length; index += 2) {
        next.push(await merkleParent(current[index], current[index + 1]));
      }
      layers.push(next);
    }

    for (let epochIndex = 0; epochIndex < epochs.length; epochIndex += 1) {
      let index = epochIndex;
      const siblings: string[] = [];
      for (const layer of layers.slice(0, -1)) {
        siblings.push(toHex(layer[index ^ 1]));
        index = Math.floor(index / 2);
      }
      epochs[epochIndex].merkleProof = siblings;
    }

    return { root: toHex(layers.at(-1)![0]), epochs };
  } finally {
    passkeyPrfOutput.fill(0);
    master?.fill(0);
  }
}

export async function deriveNextAuthorizationProof(
  context: AuthorizationContext,
  epoch: number,
  purpose: AuthorizationPurpose,
  remainingProofs: number,
  credentialId?: Uint8Array,
  onProgress?: DerivationProgress,
): Promise<string> {
  if (!PURPOSES.includes(purpose)) throw new Error('Unsupported authorization purpose.');
  if (!Number.isInteger(epoch) || epoch < 1 || epoch > AUTHORIZATION_EPOCH_COUNT) {
    throw new Error('Authorization epoch is out of range.');
  }
  if (!Number.isInteger(remainingProofs) || remainingProofs < 1 || remainingProofs > AUTHORIZATION_PROOFS_PER_EPOCH) {
    throw new Error('No valid proofs remain in this authorization chain.');
  }

  const passkeyPrfOutput = await requestPasskeyPrfOutput(context, credentialId);
  let master: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  try {
    master = await deriveMaster(passkeyPrfOutput, context, onProgress);
    seed = await derivePurposeSeed(master, context, epoch, purpose);
    let proof = seed;
    for (let step = 1; step < remainingProofs; step += 1) {
      proof = await sha256(proof);
    }
    return toHex(proof);
  } finally {
    seed?.fill(0);
    passkeyPrfOutput.fill(0);
    master?.fill(0);
  }
}


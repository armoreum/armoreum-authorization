import {
  getAddress,
  TypedDataEncoder,
  verifyTypedData,
  type TypedDataDomain,
  type TypedDataField,
} from "ethers";

export type Eip1193SigningProvider = {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
};

export async function requestWalletTypedDataSignature(
  wallet: Eip1193SigningProvider,
  accountAddress: string,
  domain: TypedDataDomain,
  types: Record<string, TypedDataField[]>,
  message: Record<string, unknown>,
): Promise<string> {
  const payload = TypedDataEncoder.getPayload(domain, types, message);
  const account = getAddress(accountAddress);
  const parameterVariants: unknown[][] = [
    [account, payload],
    [account, JSON.stringify(payload)],
  ];

  for (let index = 0; index < parameterVariants.length; index += 1) {
    let result: unknown;
    try {
      result = await wallet.request({
        method: "eth_signTypedData_v4",
        params: parameterVariants[index],
      });
    } catch (error) {
      if (index === 0 && isTypedDataParameterError(error)) continue;
      if (isTypedDataParameterError(error)) {
        throw new Error("This wallet rejected both supported EIP-712 request formats. Reconnect a wallet that supports typed-data signing; no transaction was sent.");
      }
      throw error;
    }

    if (typeof result !== "string") {
      throw new Error("The wallet did not return a typed-data signature.");
    }
    let recoveredAddress: string;
    try {
      recoveredAddress = verifyTypedData(domain, types, message, result);
    } catch {
      throw new Error("The wallet returned an invalid typed-data signature.");
    }
    if (getAddress(recoveredAddress) !== account) {
      throw new Error("The wallet signature does not match the connected creator account.");
    }
    return result;
  }

  throw new Error("The wallet could not sign this Unjail request.");
}

function isTypedDataParameterError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as {
    code?: unknown;
    message?: unknown;
    data?: { code?: unknown; message?: unknown };
    error?: { code?: unknown; message?: unknown };
    info?: { error?: { code?: unknown; message?: unknown } };
  };
  const codes = [
    candidate.code,
    candidate.data?.code,
    candidate.error?.code,
    candidate.info?.error?.code,
  ];
  const messages = [
    candidate.message,
    candidate.data?.message,
    candidate.error?.message,
    candidate.info?.error?.message,
  ].filter((value): value is string => typeof value === "string");
  return codes.some((code) => code === -32000 || code === -32602)
    && messages.some((message) => /missing or invalid parameters|invalid params/i.test(message));
}

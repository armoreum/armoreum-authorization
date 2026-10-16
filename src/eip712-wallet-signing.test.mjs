import assert from "node:assert/strict";
import { test } from "node:test";
import { TypedDataEncoder, Wallet, verifyTypedData } from "ethers";
import { requestWalletTypedDataSignature } from "./eip712-wallet-signing.ts";

const signingWallet = new Wallet(`0x${"11".repeat(32)}`);
const otherWallet = new Wallet(`0x${"22".repeat(32)}`);
const domain = {
  name: "ArmoreumCreatorRewardVault",
  version: "2",
  chainId: 1,
  verifyingContract: "0x0000000000000000000000000000000000000001",
};
const types = {
  UnjailRequest: [
    { name: "launchId", type: "bytes32" },
    { name: "creator", type: "address" },
    { name: "chainId", type: "uint256" },
    { name: "vault", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "recipient", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "credentialVersion", type: "uint256" },
  ],
};
const message = {
  launchId: `0x${"33".repeat(32)}`,
  creator: signingWallet.address,
  chainId: 1,
  vault: domain.verifyingContract,
  amount: 4741000000000000n,
  recipient: "0x0000000000000000000000000000000000000002",
  nonce: 1n,
  deadline: 1800000000n,
  credentialVersion: 1n,
};

test("uses the object-form EIP-712 request and verifies the signer", async () => {
  let callCount = 0;
  const signature = await requestWalletTypedDataSignature(
    {
      async request({ method, params }) {
        callCount += 1;
        assert.equal(method, "eth_signTypedData_v4");
        assert.equal(params[0], signingWallet.address);
        assert.deepEqual(params[1], TypedDataEncoder.getPayload(domain, types, message));
        return signingWallet.signTypedData(domain, types, message);
      },
    },
    signingWallet.address,
    domain,
    types,
    message,
  );

  assert.equal(callCount, 1);
  assert.equal(verifyTypedData(domain, types, message, signature), signingWallet.address);
});

test("retries with the JSON-string form only after an invalid-parameters response", async () => {
  let callCount = 0;
  const signature = await requestWalletTypedDataSignature(
    {
      async request({ params }) {
        callCount += 1;
        if (typeof params[1] !== "string") {
          throw Object.assign(new Error("Missing or invalid parameters."), { code: -32000 });
        }
        assert.deepEqual(JSON.parse(params[1]), TypedDataEncoder.getPayload(domain, types, message));
        return signingWallet.signTypedData(domain, types, message);
      },
    },
    signingWallet.address,
    domain,
    types,
    message,
  );

  assert.equal(callCount, 2);
  assert.equal(verifyTypedData(domain, types, message, signature), signingWallet.address);
});

test("rejects a signature from any account other than the creator", async () => {
  await assert.rejects(
    requestWalletTypedDataSignature(
      {
        async request() {
          return otherWallet.signTypedData(domain, types, message);
        },
      },
      signingWallet.address,
      domain,
      types,
      message,
    ),
    /does not match the connected creator account/,
  );
});

test("does not retry typed-data signing after the user rejects it", async () => {
  let callCount = 0;
  const rejected = Object.assign(new Error("User rejected request."), { code: 4001 });
  await assert.rejects(
    requestWalletTypedDataSignature(
      {
        async request() {
          callCount += 1;
          throw rejected;
        },
      },
      signingWallet.address,
      domain,
      types,
      message,
    ),
    (error) => error === rejected,
  );
  assert.equal(callCount, 1);
});

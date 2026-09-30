import { describe, expect, test } from "bun:test";
import {
  authenticateOperator,
  OperatorNotAuthorizedError,
  signedPost,
} from "../src/api";
import { createWriteMessage } from "../src/crypto";
import {
  connectHumid,
  deriveHumidIdentity,
  descriptorChecksum,
  type WalletDescriptorResult,
} from "../src/humid";
import type { AuthConfig } from "../src/types";

const TESTNET_XPUB =
  "tpubDCRMaF33e44pcJj534LXVhFbHibPbJ5vuLhSSPFAw57kYURv4tzXFL6LSnd78bkjqdmE3USedkbpXJUPA1tdzKfuYSL7PianceqAhwL2UkA";

function descriptorResult(descriptor: string): WalletDescriptorResult {
  return {
    accountIdentifier: "bip122:test:wallet",
    chainId: "bip122:test",
    descriptors: [
      {
        branchLayout: "split",
        descriptorType: "publicWalletDescriptor",
        format: "bip380-split-branches",
        branchDescriptors: [
          { branch: "external", change: 0, descriptor },
          { branch: "internal", change: 1, descriptor: "unused" },
        ],
      },
    ],
  };
}

describe("Humid authentication protocol", () => {
  test("adds a first-time regtest chain using the local Esplora API", async () => {
    const chainId = "bip122:new-regtest";
    const expression = `elwpkh([759db348/84'/1'/0']${TESTNET_XPUB}/0/*)`;
    const calls: string[] = [];
    const provider = {
      async request({ method, params }: { method: string; params?: unknown }) {
        calls.push(method);

        if (method === "wallet_addChain") {
          expect(params).toEqual({
            name: "HighStorm Elements Regtest",
            settings: {
              network: "regtest",
              backend: { url: "http://127.0.0.1:3001" },
            },
          });
          return { chainId };
        }
        if (method === "wallet_createSession") return { sessionScopes: {} };
        if (method === "wallet_invokeMethod") {
          return {
            ...descriptorResult(
              `${expression}#${descriptorChecksum(expression)}`,
            ),
            chainId,
          };
        }

        throw new Error(`Unexpected Humid method: ${method}`);
      },
    };
    const storage = new Map<string, string>();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { humid: provider },
    });
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => storage.set(key, value),
      },
    });
    const config: AuthConfig = {
      network: "elementsregtest",
      caip2_chain_id: null,
      signature_scheme: "bitcoin-signed-message-ecdsa-v1",
      descriptor_type: "publicWalletDescriptor",
      descriptor_format: "bip380-split-branches",
      identity_derivation: { branch: 0, index: 0 },
    };

    try {
      const identity = await connectHumid(config);

      expect(identity.chainId).toBe(chainId);
      expect(storage.get("storm-humid-regtest-chain")).toBe(chainId);
      expect(calls).toEqual([
        "wallet_addChain",
        "wallet_createSession",
        "wallet_invokeMethod",
      ]);
    } finally {
      delete (globalThis as { window?: unknown }).window;
      delete (globalThis as { localStorage?: unknown }).localStorage;
    }
  });

  test("creates a session before using a stored regtest chain", async () => {
    const chainId = "bip122:stored-regtest";
    const expression = `elwpkh([759db348/84'/1'/0']${TESTNET_XPUB}/0/*)`;
    const calls: string[] = [];
    let sessionCreated = false;
    const provider = {
      async request({ method }: { method: string }) {
        calls.push(method);

        if (method === "wallet_switchChain" && !sessionCreated) {
          throw Object.assign(
            new Error('No active session. Call "wallet_createSession" first.'),
            { code: 4100 },
          );
        }
        if (method === "wallet_createSession") {
          sessionCreated = true;
          return { sessionScopes: {} };
        }
        if (method === "wallet_invokeMethod") {
          return {
            ...descriptorResult(
              `${expression}#${descriptorChecksum(expression)}`,
            ),
            chainId,
          };
        }

        throw new Error(`Unexpected Humid method: ${method}`);
      },
    };
    const storage = new Map([["storm-humid-regtest-chain", chainId]]);
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { humid: provider },
    });
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => storage.get(key) ?? null,
        removeItem: (key: string) => storage.delete(key),
        setItem: (key: string, value: string) => storage.set(key, value),
      },
    });
    const config: AuthConfig = {
      network: "liquidtestnet",
      caip2_chain_id: null,
      signature_scheme: "bitcoin-signed-message-ecdsa-v1",
      descriptor_type: "publicWalletDescriptor",
      descriptor_format: "bip380-split-branches",
      identity_derivation: { branch: 0, index: 0 },
    };

    try {
      const identity = await connectHumid(config);

      expect(identity.chainId).toBe(chainId);
      expect(calls).toEqual(["wallet_createSession", "wallet_invokeMethod"]);
    } finally {
      delete (globalThis as { window?: unknown }).window;
      delete (globalThis as { localStorage?: unknown }).localStorage;
    }
  });

  test("matches the BIP380 checksum from an LWK descriptor vector", () => {
    const descriptor =
      "ct(slip77(ab5824f4477b4ebb00a132adfd8eb0b7935cf24f6ac151add5d1913db374ce92),elwpkh([759db348/84'/1'/0']tpubDCRMaF33e44pcJj534LXVhFbHibPbJ5vuLhSSPFAw57kYURv4tzXFL6LSnd78bkjqdmE3USedkbpXJUPA1tdzKfuYSL7PianceqAhwL2UkA/<0;1>/*))";

    expect(descriptorChecksum(descriptor)).toBe("cch6wrnp");
  });

  test("constructs the canonical v2 signed-write message", async () => {
    await expect(
      createWriteMessage("post", "/operators/voting", 123, "nonce", {
        b: 2,
        a: 1,
      }),
    ).resolves.toBe(
      [
        "high-storm:operator-write:v2",
        "bitcoin-signed-message-ecdsa-v1",
        "POST",
        "/operators/voting",
        "123",
        "nonce",
        "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
      ].join("\n"),
    );
  });

  test("sends a signed voting action with the approved Humid message", async () => {
    const originalFetch = globalThis.fetch;
    const publicKey =
      "0321da398ca2ddc09be89caa26e6730ae84751b6ea3a1ca46aa365bb5e1c3d9620";
    let signedMessage = "";
    let sentBody: Record<string, unknown> = {};
    globalThis.fetch = async (input, init) => {
      expect(input).toBe("/operators/voting/test-hash/approve");
      sentBody = JSON.parse(String(init?.body));
      return new Response(null, { status: 204 });
    };

    try {
      await signedPost(
        {
          token: "test-token",
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          identity: {
            publicKey,
            address: "tex1qtest",
            network: "liquidtestnet",
            chainId: "bip122:test",
            accountIdentifier: "bip122:test:wallet",
            sign: async (message) => {
              signedMessage = message;
              return "ab".repeat(65);
            },
          },
        },
        "/operators/voting/test-hash/approve",
        {},
      );

      expect(signedMessage).toBe(
        await createWriteMessage(
          "POST",
          "/operators/voting/test-hash/approve",
          sentBody.timestamp as number,
          sentBody.nonce as string,
          {},
        ),
      );
      expect(sentBody).toEqual({
        public_key: publicKey,
        signature_scheme: "bitcoin-signed-message-ecdsa-v1",
        timestamp: sentBody.timestamp,
        nonce: sentBody.nonce,
        signature: "ab".repeat(65),
        payload: {},
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("reports the derived operator identifier when it is unauthorized", async () => {
    const publicKey =
      "0321da398ca2ddc09be89caa26e6730ae84751b6ea3a1ca46aa365bb5e1c3d9620";
    const originalFetch = globalThis.fetch;
    let signed = false;
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ error: "operator is not authorized" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });

    try {
      const authentication = authenticateOperator({
        publicKey,
        address: "tex1qtest",
        network: "liquidtestnet",
        chainId: "bip122:test",
        accountIdentifier: "bip122:test:wallet",
        sign: async () => {
          signed = true;
          return "";
        },
      });

      await expect(authentication).rejects.toEqual(
        new OperatorNotAuthorizedError(publicKey),
      );
      expect(signed).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("derives the fixed external index zero identity", () => {
    const expression = `elwpkh([759db348/84'/1'/0']${TESTNET_XPUB}/0/*)`;
    const identity = deriveHumidIdentity(
      descriptorResult(`${expression}#${descriptorChecksum(expression)}`),
      "liquidtestnet",
    );

    expect(identity.publicKey).toBe(
      "0321da398ca2ddc09be89caa26e6730ae84751b6ea3a1ca46aa365bb5e1c3d9620",
    );
    expect(identity.address).toBe(
      "tex1q3la4j2yfhhgxh2h66p4l4z98x4363k7dqnz79t",
    );
  });

  test("rejects a descriptor with an invalid checksum", () => {
    const expression = `elwpkh([759db348/84'/1'/0']${TESTNET_XPUB}/0/*)`;

    expect(() =>
      deriveHumidIdentity(
        descriptorResult(`${expression}#aaaaaaaa`),
        "liquidtestnet",
      ),
    ).toThrow("invalid checksum");
  });
});

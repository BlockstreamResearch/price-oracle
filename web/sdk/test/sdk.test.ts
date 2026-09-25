import { describe, expect, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1";

import {
  PriceOracleClient,
  createTickRequest,
  createTickSpendPlan,
  decodePriceData,
  publicKeyFromPrivateKey,
  signSchnorrDigest,
  tickRequestSigningHash,
  verifySignedPriceData,
} from "../src";

const PRIVATE_KEY = "1f".repeat(32);
/** Feed 4 at 100.00000000, as the coordinator encodes and signs it. */
const PRICE_DATA =
  "000000040000000800000002540be400000000006553f100000000006553f22c";
/** The `OracleNetworkV1/Price` message over PRICE_DATA, pinned in Rust too. */
const PRICE_MESSAGE =
  "dd5c6a22d1a989ec39cfcd82b64d8e1f43bcca770dc3d2949022a9808b3d6340";

describe("Price Oracle SDK", () => {
  test("derives an x-only key and signs coordinator Tick requests", () => {
    const request = createTickRequest(PRIVATE_KEY, [`${"ab".repeat(32)}:1`]);

    expect(request.header.public_key).toBe(
      publicKeyFromPrivateKey(PRIVATE_KEY),
    );
    expect(
      schnorr.verify(
        request.header.signature,
        tickRequestSigningHash(request),
        request.header.public_key,
      ),
    ).toBe(true);
  });

  test("signs a covenant digest with the owner key", () => {
    expect(signSchnorrDigest(PRIVATE_KEY, "ab".repeat(32))).toHaveLength(128);
  });

  test("fetches the canonical account from the coordinator", async () => {
    const publicKey = publicKeyFromPrivateKey(PRIVATE_KEY);
    const client = new PriceOracleClient(
      "http://coordinator.test/",
      async (request) => {
        expect(String(request)).toBe(
          `http://coordinator.test/users/account/${publicKey}`,
        );
        return Response.json({
          address: "ert1ptest",
          script_pubkey: "5120" + "00".repeat(32),
          storm_eye_asset_id: "01".repeat(32),
          tick_asset_id: "02".repeat(32),
          tick_script_pubkey: "5120" + "03".repeat(32),
          network: "elementsregtest",
        });
      },
    );

    expect((await client.getAccount(publicKey)).network).toBe(
      "elementsregtest",
    );
  });

  test("invokes fetch with its browser global receiver", async () => {
    const publicKey = publicKeyFromPrivateKey(PRIVATE_KEY);
    const fetcher = function (this: typeof globalThis) {
      expect(this).toBe(globalThis);
      return Promise.resolve(Response.json({ network: "elementsregtest" }));
    } as typeof globalThis.fetch;

    expect(
      (
        await new PriceOracleClient(
          "http://coordinator.test",
          fetcher,
        ).getAccount(publicKey)
      ).network,
    ).toBe("elementsregtest");
  });

  test("requires a Tick after the signed occurrence time", () => {
    expect(() =>
      createTickSpendPlan(
        {
          txid: "02".repeat(32),
          vout: 1,
          asset: "03".repeat(32),
          timestamp: 99,
          scriptPubKey: "51",
        },
        {
          predictionId: "04".repeat(32),
          occurredAt: 100,
          signature: "05".repeat(64),
        },
      ),
    ).toThrow("Tick timestamp");
  });

  test("sets an exact burn allowance for Tick redemption broadcasts", async () => {
    const fetcher = async (_request: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.method).toBe("sendrawtransaction");
      expect(body.params).toEqual(["00", 0.1, 1.25]);
      return Response.json({ result: "txid", error: null });
    };

    const rpc = new (await import("../src")).ElementsRpcClient({
      url: "http://elements.test",
      fetch: fetcher as typeof globalThis.fetch,
    });
    expect(await rpc.broadcast("00", 125_000_000)).toBe("txid");
  });

  test("reads transaction confirmations from Elements RPC", async () => {
    const fetcher = async (_request: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.method).toBe("getrawtransaction");
      expect(body.params).toEqual(["ab".repeat(32), true]);
      return Response.json({ result: { confirmations: 2 }, error: null });
    };
    const rpc = new (await import("../src")).ElementsRpcClient({
      url: "http://elements.test",
      fetch: fetcher as typeof globalThis.fetch,
    });

    expect(await rpc.getTransactionConfirmations("ab".repeat(32))).toBe(2);
  });

  test("reads the canonical price bytes the network signs", () => {
    expect(decodePriceData(PRICE_DATA)).toEqual({
      feedId: 4,
      decimals: 8,
      price: 10_000_000_000n,
      receivedAt: 1_700_000_000n,
      validUntil: 1_700_000_300n,
    });
  });

  test("accepts a network signature over the rate and rejects another rate", () => {
    const branch = publicKeyFromPrivateKey(PRIVATE_KEY);
    const details = {
      timestamp: 1_700_000_000,
      price_data: PRICE_DATA,
      storm_tree_bloom: {
        signature: signSchnorrDigest(PRIVATE_KEY, PRICE_MESSAGE),
        branch,
        proof: [{ right: true, hash: "03".repeat(32) }],
      },
    };

    expect(verifySignedPriceData(details)).toBe(true);
    expect(
      verifySignedPriceData({
        ...details,
        price_data: PRICE_DATA.replace(/.$/, "d"),
      }),
    ).toBe(false);
  });
});

import { describe, expect, test } from "bun:test";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";

import {
  PriceOracleClient,
  createSignedPriceRequest,
  createTickRequest,
  createWalletTickRequest,
  walletRequestSigningMessage,
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
  test("builds a Humid-authorized Tick request without a private key", () => {
    const publicKey = Buffer.from(secp256k1.getPublicKey(PRIVATE_KEY)).toString(
      "hex",
    );
    const fee = `${"ab".repeat(32)}:1`;
    const walletScript = `0014${"55".repeat(20)}`;
    const request = createWalletTickRequest(publicKey, [fee], walletScript);
    expect(request.header.signature).toBe("");
    expect(request.header.public_key).toBe(publicKey.slice(2));
    expect(request.header.signing_public_key).toBe(publicKey);
    const message = walletRequestSigningMessage(request);
    expect(message).toBe(
      `OracleNetworkV1/NetworkUserRequests\nbitcoin-signed-message-ecdsa-v1\n${JSON.stringify(
        [
          publicKey.slice(2),
          publicKey,
          [fee],
          [
            {
              kind: "tick-utxo",
              payload: JSON.stringify({
                utxo_auth_method: {
                  kind: "scriptPubKey-auth",
                  auth_data: walletScript,
                },
              }),
            },
          ],
        ],
      )}`,
    );
    request.header.signature = "signed-by-wallet";
    expect(walletRequestSigningMessage(request)).toBe(message);
    request.header.fee_utxos[0] = `${"ab".repeat(32)}:2`;
    expect(walletRequestSigningMessage(request)).not.toBe(message);
    expect(() =>
      createWalletTickRequest(publicKey.slice(2), [fee], walletScript),
    ).toThrow();
    expect(() =>
      createWalletTickRequest(publicKey, [], walletScript),
    ).toThrow();
  });

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

  test("builds a request issued at a price feed that the network accepts", () => {
    const request = createSignedPriceRequest(
      PRIVATE_KEY,
      [`${"ab".repeat(32)}:1`],
      4,
    );

    expect(request.requests.map(({ kind }) => kind)).toEqual([
      "signed-price-data",
    ]);
    // The field is spelled as the specification spells it, and nothing else
    // rides along: the network rejects an unknown field outright, so either
    // mistake is a 400 rather than a default.
    expect(request.requests.map(({ payload }) => JSON.parse(payload))).toEqual([
      {
        utxo_auth_method: {
          kind: "signature-auth",
          auth_data: publicKeyFromPrivateKey(PRIVATE_KEY),
        },
        price_feed_id: 4,
      },
    ]);
    // The signing hash covers the payloads, so it covers the feed it names.
    expect(
      schnorr.verify(
        request.header.signature,
        tickRequestSigningHash(request),
        request.header.public_key,
      ),
    ).toBe(true);
  });

  test("keeps a plain Tick request free of any price feed", () => {
    const payloads = createTickRequest(PRIVATE_KEY, [
      `${"ab".repeat(32)}:1`,
    ]).requests.map(({ payload }) => JSON.parse(payload) as object);

    // A Tick naming a feed is rejected, so the key is absent entirely rather
    // than present and empty.
    expect(payloads.map((payload) => "price_feed_id" in payload)).toEqual([
      false,
    ]);
  });

  test("refuses a feed id the network cannot encode", () => {
    const feeUtxos = [`${"ab".repeat(32)}:1`];

    expect(() => createSignedPriceRequest(PRIVATE_KEY, feeUtxos, -1)).toThrow();
    expect(() =>
      createSignedPriceRequest(PRIVATE_KEY, feeUtxos, 1.5),
    ).toThrow();
    expect(() =>
      createSignedPriceRequest(PRIVATE_KEY, feeUtxos, 0x1_0000_0000),
    ).toThrow();
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
          oracle_verifier_asset_id: "04".repeat(32),
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

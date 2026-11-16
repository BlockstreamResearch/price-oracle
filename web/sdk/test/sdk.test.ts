import { describe, expect, test } from "bun:test";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import {
  ElementsRpcClient,
  ElementsRpcError,
  EsploraClient,
  EsploraError,
  OracleApiError,
  PriceOracleClient,
  deriveAccount,
  createSignedPriceRequest,
  createTickRequest,
  createWalletTickRequest,
  createWalletSignedPriceRequest,
  parseExecutedSignedPrice,
  walletRequestSigningMessage,
  createTickSpendPlan,
  decodePriceData,
  publicKeyFromPrivateKey,
  signSchnorrDigest,
  tickRequestSigningHash,
  verifySignedPriceData,
  verifyExecutedSignedPrice,
  verifyExecutedTick,
  type AccountVerification,
  type ChainOutput,
  type NetworkVerification,
} from "../src";

const PRIVATE_KEY = "1f".repeat(32);
/** Feed 4 at 100.00000000, as the coordinator encodes and signs it. */
const PRICE_DATA =
  "000000040000000800000002540be400000000006553f100000000006553f22c";
/** The `OracleNetworkV1/Price` message over PRICE_DATA, pinned in Rust too. */
const PRICE_MESSAGE =
  "dd5c6a22d1a989ec39cfcd82b64d8e1f43bcca770dc3d2949022a9808b3d6340";

const BRANCH = publicKeyFromPrivateKey(PRIVATE_KEY);
const ACCOUNT_VERIFICATION = {
  ownerPublicKey: BRANCH,
  network: "elementsregtest" as const,
  stormEyeAssetId: "01".repeat(32),
  tickAssetId: "02".repeat(32),
  verifierAssetId: "04".repeat(32),
  accountTapleafHash:
    "d1754012c445c3df09b0d1bec1d6fb3addd9678ccc11e3a2833b5bb6b73a7119",
  tickTapleafHash:
    "c94377a3c786b6aefba98ca7e7c2e6ca6a9a4d6ddbdbf20a17fbc32f846be9a4",
};
const ACCOUNT = {
  address: "ert1pkmmvkxqa77evn3fvqjuat2dqrf6xnwtnfau9yycpwjh6acsd9ezsmggutc",
  script_pubkey:
    "5120b6f6cb181df7b2c9c52c04b9d5a9a01a7469b9734f7852130174afaee20d2e45",
  storm_eye_asset_id: "01".repeat(32),
  tick_asset_id: "02".repeat(32),
  tick_script_pubkey:
    "5120c34ad1035500f2c8e74a71f36e22ff83cb0094b6fe950b86a709b534b4b226e5",
  oracle_verifier_asset_id: "04".repeat(32),
  network: "elementsregtest",
};
const PROOF = [{ right: true, hash: "03".repeat(32) }];
const VERIFICATION = {
  stormTreeRoot:
    "18b14ea9ec5e0932131a6d2b421c992b9cdde6a15059e14da69388174a6b2098",
  feedId: 4,
  decimals: 8,
  now: 1_700_000_100n,
};

describe("Price Oracle SDK", () => {
  test("reads the deployed price-feed endpoints", async () => {
    const urls: string[] = [];
    const client = new PriceOracleClient(
      "https://coordinator.test",
      async (request) => {
        urls.push(String(request));
        return Response.json({});
      },
    );
    await client.getPriceFeeds();
    await client.getPriceFeed(0);
    expect(urls).toEqual([
      "https://coordinator.test/price-feeds",
      "https://coordinator.test/price-feeds/0",
    ]);
  });

  test("builds wallet-priced batches with a signature binding the feed", () => {
    const publicKey = Buffer.from(secp256k1.getPublicKey(PRIVATE_KEY)).toString(
      "hex",
    );
    const request = createWalletSignedPriceRequest(
      publicKey,
      [`${"ab".repeat(32)}:1`],
      `0014${"55".repeat(20)}`,
      0,
      { withTick: true },
    );
    expect(request.requests.map(({ kind }) => kind)).toEqual([
      "signed-price-data",
      "tick-utxo",
    ]);
    expect(JSON.parse(request.requests[0].payload).price_feed_id).toBe(0);
    expect(
      JSON.parse(request.requests[1].payload).price_feed_id,
    ).toBeUndefined();
    const message = walletRequestSigningMessage(request);
    request.requests[0].payload = request.requests[0].payload.replace(
      '"price_feed_id":0',
      '"price_feed_id":4',
    );
    expect(walletRequestSigningMessage(request)).not.toBe(message);
    for (const invalid of [-1, 0.5, 0x100000000])
      expect(() =>
        createWalletSignedPriceRequest(
          publicKey,
          [`${"ab".repeat(32)}:1`],
          `0014${"55".repeat(20)}`,
          invalid,
        ),
      ).toThrow();
  });

  test("parses a finalized Verifier and rejects forged prices or premature issuance", () => {
    const signedPrice = {
      price_data: PRICE_DATA,
      storm_tree_bloom: {
        branch: publicKeyFromPrivateKey(PRIVATE_KEY),
        signature: signSchnorrDigest(PRIVATE_KEY, PRICE_MESSAGE),
        proof: PROOF,
      },
    };
    const payload = JSON.stringify({
      txid: "ab".repeat(32),
      results: [
        {
          kind: "signed-price-data",
          vout: 3,
          payload: JSON.stringify(signedPrice),
        },
      ],
    });
    for (const status of ["pending", "processing", "included"] as const)
      expect(
        parseExecutedSignedPrice({ status, payload }, VERIFICATION),
      ).toBeNull();
    expect(
      parseExecutedSignedPrice({ status: "executed", payload }, VERIFICATION)
        ?.verifierVout,
    ).toBe(3);
    expect(() =>
      parseExecutedSignedPrice(
        {
          status: "executed",
          payload: payload.replace(PRICE_DATA, "00".repeat(32)),
        },
        VERIFICATION,
      ),
    ).toThrow();
    expect(() =>
      parseExecutedSignedPrice(
        {
          status: "executed",
          payload: JSON.stringify({ txid: "ab".repeat(32), results: [] }),
        },
        VERIFICATION,
      ),
    ).toThrow();
    expect(() =>
      parseExecutedSignedPrice(
        { status: "executed", payload },
        {
          ...VERIFICATION,
          stormTreeRoot: "00".repeat(32),
        },
      ),
    ).toThrow("trusted context");
    expect(() =>
      parseExecutedSignedPrice(
        { status: "executed", payload },
        {
          ...VERIFICATION,
          now: 1_700_000_300n,
        },
      ),
    ).toThrow("trusted context");
  });

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
      "https://coordinator.test/",
      async (request) => {
        expect(String(request)).toBe(
          `https://coordinator.test/users/account/${publicKey}`,
        );
        return Response.json(ACCOUNT);
      },
    );

    expect(deriveAccount(ACCOUNT_VERIFICATION)).toEqual(ACCOUNT);
    expect(await client.getAccount(publicKey, ACCOUNT_VERIFICATION)).toEqual(
      ACCOUNT,
    );
  });

  test("invokes fetch with its browser global receiver", async () => {
    const publicKey = publicKeyFromPrivateKey(PRIVATE_KEY);
    const fetcher = function (this: typeof globalThis) {
      expect(this).toBe(globalThis);
      return Promise.resolve(Response.json(ACCOUNT));
    } as typeof globalThis.fetch;

    expect(
      (
        await new PriceOracleClient(
          "https://coordinator.test",
          fetcher,
        ).getAccount(publicKey, ACCOUNT_VERIFICATION)
      ).network,
    ).toBe("elementsregtest");
  });

  test("matches Rust-derived Account addresses on all supported networks", () => {
    for (const [network, address] of [
      [
        "liquidv1",
        "ex1pkmmvkxqa77evn3fvqjuat2dqrf6xnwtnfau9yycpwjh6acsd9ezsv9h7d0",
      ],
      [
        "liquidtestnet",
        "tex1pkmmvkxqa77evn3fvqjuat2dqrf6xnwtnfau9yycpwjh6acsd9ezsdu9euq",
      ],
      ["elementsregtest", ACCOUNT.address],
    ] as const) {
      expect(deriveAccount({ ...ACCOUNT_VERIFICATION, network })).toEqual({
        ...ACCOUNT,
        address,
        network,
      });
    }
  });

  test("verifies the full script-authorized Tick and preserves the auth query", async () => {
    const authScriptPubKey = `0014${"55".repeat(20)}`;
    const verification = {
      ...ACCOUNT_VERIFICATION,
      authScriptPubKey,
      tickTapleafHash:
        "88367e67f5f27e1aa2e906627cc1b57777489d93c7f48554065602d275c1391a",
    };
    const expected = {
      ...ACCOUNT,
      tick_script_pubkey:
        "5120f84a9ece5e4fab1c3c166a27e6695bd715058afe75074ff6c879de19495a81b7",
    };
    const client = new PriceOracleClient(
      "https://coordinator.test",
      async (request) => {
        expect(String(request)).toBe(
          `https://coordinator.test/users/account/${BRANCH}?auth_script_pubkey=${authScriptPubKey}`,
        );
        return Response.json(expected);
      },
    );

    expect(deriveAccount(verification)).toEqual(expected);
    expect(await client.getAccount(BRANCH, verification)).toEqual(expected);

    const wrongAuth = new PriceOracleClient(
      "https://coordinator.test",
      async () => Response.json(ACCOUNT),
    );
    await expect(wrongAuth.getAccount(BRANCH, verification)).rejects.toThrow(
      "tick_script_pubkey",
    );
  });

  test("rejects coordinator substitutions for every Account response field", async () => {
    const substitutions = {
      address: "ert1pattacker",
      script_pubkey: `5120${"99".repeat(32)}`,
      tick_script_pubkey: `5120${"98".repeat(32)}`,
      storm_eye_asset_id: "97".repeat(32),
      tick_asset_id: "96".repeat(32),
      oracle_verifier_asset_id: "95".repeat(32),
      network: "liquidv1",
    };

    for (const [field, value] of Object.entries(substitutions)) {
      const client = new PriceOracleClient(
        "https://coordinator.test",
        async () => Response.json({ ...ACCOUNT, [field]: value }),
      );
      await expect(
        client.getAccount(BRANCH, ACCOUNT_VERIFICATION),
      ).rejects.toThrow(field);
    }

    for (const body of [
      null,
      {},
      { ...ACCOUNT, script_pubkey: 123 },
      { ...ACCOUNT, tick_asset_id: null },
    ]) {
      const client = new PriceOracleClient(
        "https://coordinator.test",
        async () => Response.json(body),
      );
      await expect(
        client.getAccount(BRANCH, ACCOUNT_VERIFICATION),
      ).rejects.toThrow("trusted derivation");
    }
  });

  test("rejects malformed trust context and owner mismatches before fetching", async () => {
    let fetched = false;
    const client = new PriceOracleClient(
      "https://coordinator.test",
      async () => {
        fetched = true;
        return Response.json(ACCOUNT);
      },
    );
    const invalid = [
      undefined,
      {},
      { ...ACCOUNT_VERIFICATION, ownerPublicKey: "00".repeat(32) },
      {
        ...ACCOUNT_VERIFICATION,
        ownerPublicKey: publicKeyFromPrivateKey("02".repeat(32)),
      },
      { ...ACCOUNT_VERIFICATION, network: "bitcoin" },
      { ...ACCOUNT_VERIFICATION, authScriptPubKey: "not-hex" },
      ...[
        "stormEyeAssetId",
        "tickAssetId",
        "verifierAssetId",
        "accountTapleafHash",
        "tickTapleafHash",
      ].map((field) => ({ ...ACCOUNT_VERIFICATION, [field]: "not-hex" })),
    ];

    for (const verification of invalid)
      await expect(
        client.getAccount(BRANCH, verification as AccountVerification),
      ).rejects.toThrow();

    expect(fetched).toBe(false);
  });

  test("rejects internally consistent coordinator data with untrusted contract leaves", async () => {
    const attacker = deriveAccount({
      ...ACCOUNT_VERIFICATION,
      accountTapleafHash: "99".repeat(32),
      tickTapleafHash: "98".repeat(32),
    });
    const client = new PriceOracleClient("https://coordinator.test", async () =>
      Response.json(attacker),
    );

    await expect(
      client.getAccount(BRANCH, ACCOUNT_VERIFICATION),
    ).rejects.toThrow("trusted derivation");
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

    expect(verifySignedPriceData(details, VERIFICATION)).toBe(true);
    expect(
      verifySignedPriceData(
        {
          ...details,
          price_data: PRICE_DATA.replace("540be4", "540be5"),
        },
        VERIFICATION,
      ),
    ).toBe(false);
  });

  test("rejects self-signed attacker prices and incorrect proofs", () => {
    const details = {
      price_data: PRICE_DATA,
      storm_tree_bloom: {
        signature: signSchnorrDigest(PRIVATE_KEY, PRICE_MESSAGE),
        branch: BRANCH,
        proof: PROOF,
      },
    };
    const attackerKey = "20".repeat(32);
    const attacker = {
      ...details,
      storm_tree_bloom: {
        ...details.storm_tree_bloom,
        branch: publicKeyFromPrivateKey(attackerKey),
        signature: signSchnorrDigest(attackerKey, PRICE_MESSAGE),
      },
    };
    expect(verifySignedPriceData(attacker, VERIFICATION)).toBe(false);
    for (const proof of [
      [],
      [{ right: false, hash: PROOF[0].hash }],
      [{ right: true, hash: "04".repeat(32) }],
      Array(21).fill(PROOF[0]),
      [{ right: true, hash: "xx".repeat(32) }],
    ]) {
      expect(
        verifySignedPriceData(
          {
            ...details,
            storm_tree_bloom: { ...details.storm_tree_bloom, proof },
          },
          VERIFICATION,
        ),
      ).toBe(false);
    }
    expect(
      verifySignedPriceData(details, {
        ...VERIFICATION,
        stormTreeRoot: "00".repeat(32),
      }),
    ).toBe(false);
  });

  test("requires the expected feed, decimals and a currently valid price", () => {
    const details = {
      price_data: PRICE_DATA,
      storm_tree_bloom: {
        signature: signSchnorrDigest(PRIVATE_KEY, PRICE_MESSAGE),
        branch: BRANCH,
        proof: PROOF,
      },
    };
    for (const override of [
      { feedId: 5 },
      { decimals: 9 },
      { now: 1_699_999_999n },
      { now: 1_700_000_300n },
      { now: -1n },
    ]) {
      expect(
        verifySignedPriceData(details, {
          ...VERIFICATION,
          ...override,
        }),
      ).toBe(false);
    }
    expect(
      verifySignedPriceData(details, {
        ...VERIFICATION,
        now: 1_700_000_000n,
      }),
    ).toBe(true);
    expect(
      verifySignedPriceData(details, {
        ...VERIFICATION,
        now: 1_700_000_299n,
      }),
    ).toBe(true);
  });

  test("requires HTTPS outside loopback and refuses redirects", async () => {
    for (const url of ["http://coordinator.test", "ftp://coordinator.test"])
      expect(() => new PriceOracleClient(url)).toThrow("HTTPS");
    for (const url of [
      "http://localhost:9100",
      "http://127.0.0.1:9100",
      "http://[::1]:9100",
    ])
      expect(() => new PriceOracleClient(url)).not.toThrow();
    const oracle = new PriceOracleClient(
      "https://coordinator.test",
      async (_, init) => {
        expect(init?.redirect).toBe("error");
        return Response.json([]);
      },
    );
    await oracle.getPriceFeeds();
  });

  test("fails closed without trusted context or with malformed response data", () => {
    const details = {
      price_data: PRICE_DATA,
      storm_tree_bloom: {
        signature: signSchnorrDigest(PRIVATE_KEY, PRICE_MESSAGE),
        branch: BRANCH,
        proof: PROOF,
      },
    };
    expect(Reflect.apply(verifySignedPriceData, undefined, [details])).toBe(
      false,
    );
    for (const malformed of [
      null,
      {},
      { ...details, price_data: "zz".repeat(32) },
      { ...details, price_data: "00" },
      { ...details, storm_tree_bloom: null },
      {
        ...details,
        storm_tree_bloom: { ...details.storm_tree_bloom, proof: [null] },
      },
      {
        ...details,
        storm_tree_bloom: { ...details.storm_tree_bloom, signature: "00" },
      },
      {
        ...details,
        storm_tree_bloom: {
          ...details.storm_tree_bloom,
          branch: "ff".repeat(32),
        },
      },
    ]) {
      expect(
        Reflect.apply(verifySignedPriceData, undefined, [
          malformed,
          VERIFICATION,
        ]),
      ).toBe(false);
    }
  });

  test("rejects invalid validity windows even with an authentic signature", () => {
    const tagHash = sha256(new TextEncoder().encode("OracleNetworkV1/Price"));
    for (const validUntil of [1_700_000_000n, 1_699_999_999n, 1_700_000_301n]) {
      const bytes = hexToBytes(PRICE_DATA);
      new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      ).setBigUint64(24, validUntil);
      const message = sha256(
        new Uint8Array([...tagHash, ...tagHash, ...bytes]),
      );
      const details = {
        price_data: bytesToHex(bytes),
        storm_tree_bloom: {
          signature: signSchnorrDigest(PRIVATE_KEY, bytesToHex(message)),
          branch: BRANCH,
          proof: PROOF,
        },
      };
      expect(verifySignedPriceData(details, VERIFICATION)).toBe(false);
    }
  });

  test("checks a confirmed unspent Verifier with the right asset and branch-committed script", async () => {
    const verification = {
      ...VERIFICATION,
      verifierAssetId: "04".repeat(32),
      verifierTapleafHash: "05".repeat(32),
    };
    const signedPrice = {
      price_data: PRICE_DATA,
      storm_tree_bloom: {
        branch: BRANCH,
        signature: signSchnorrDigest(PRIVATE_KEY, PRICE_MESSAGE),
        proof: PROOF,
      },
    };
    const status = {
      status: "executed" as const,
      payload: JSON.stringify({
        txid: "ab".repeat(32),
        results: [
          {
            kind: "signed-price-data",
            vout: 3,
            payload: JSON.stringify(signedPrice),
          },
        ],
      }),
    };
    const utxo = {
      confirmations: 2,
      asset: verification.verifierAssetId,
      value: 0.00000001,
      scriptPubKey: {
        hex: "512048bd0653a96f933e9132843281a8d981037ca8342a6a8941039293c69d0b8e91",
      },
    };
    let rpcResult: unknown = utxo;
    const rpc = new ElementsRpcClient({
      url: "http://127.0.0.1:18884",
      fetch: async (_, init) => {
        const request = JSON.parse(String(init?.body));
        expect(request.method).toBe("gettxout");
        expect(request.params).toEqual(["ab".repeat(32), 3, true]);
        return Response.json({ result: rpcResult, error: null });
      },
    });
    expect(
      (await verifyExecutedSignedPrice(status, verification, rpc))
        ?.verifierVout,
    ).toBe(3);
    for (const result of [
      null,
      { ...utxo, confirmations: 0 },
      { ...utxo, asset: "06".repeat(32) },
      { ...utxo, asset: undefined },
      { ...utxo, value: 0.00000002 },
      { ...utxo, value: undefined },
      { ...utxo, scriptPubKey: { hex: `5120${BRANCH}` } },
    ]) {
      rpcResult = result;
      await expect(
        verifyExecutedSignedPrice(status, verification, rpc),
      ).rejects.toThrow("Verifier");
    }
    rpcResult = utxo;
    await expect(
      verifyExecutedSignedPrice(
        status,
        {
          ...verification,
          verifierTapleafHash: "06".repeat(32),
        },
        rpc,
      ),
    ).rejects.toThrow("Verifier");
  });

  test("reads network metadata and holds it against pinned values", async () => {
    const network = {
      network: "elementsregtest",
      storm_eye_asset_id: "01".repeat(32),
      storm_tree_root: VERIFICATION.stormTreeRoot,
      tick_asset_id: "02".repeat(32),
      oracle_verifier_asset_id: "04".repeat(32),
    };
    const pinned = {
      network: "elementsregtest" as const,
      stormEyeAssetId: "01".repeat(32),
      stormTreeRoot: VERIFICATION.stormTreeRoot,
      tickAssetId: "02".repeat(32),
      verifierAssetId: "04".repeat(32),
    };
    let body: unknown = network;
    let fetched = 0;
    const client = new PriceOracleClient(
      "https://coordinator.test",
      async (request) => {
        fetched += 1;
        expect(String(request)).toBe("https://coordinator.test/users/network");
        return Response.json(body);
      },
    );

    expect(await client.getNetwork()).toEqual(network);
    expect(await client.getNetwork(pinned)).toEqual(network);
    expect(await client.getNetwork({ tickAssetId: "02".repeat(32) })).toEqual(
      network,
    );

    for (const [field, value] of Object.entries({
      network: "liquidv1",
      stormEyeAssetId: "97".repeat(32),
      stormTreeRoot: "96".repeat(32),
      tickAssetId: "95".repeat(32),
      verifierAssetId: "94".repeat(32),
    }))
      await expect(
        client.getNetwork({ ...pinned, [field]: value }),
      ).rejects.toThrow("trusted value");

    // Hex is compared and returned without regard to its case.
    body = {
      ...network,
      storm_tree_root: network.storm_tree_root.toUpperCase(),
    };
    expect(await client.getNetwork(pinned)).toEqual(network);

    // A response that cannot be read is refused with nothing pinned too.
    for (const malformed of [
      null,
      {},
      { ...network, network: "bitcoin" },
      { ...network, storm_tree_root: "00" },
      { ...network, tick_asset_id: 5 },
    ]) {
      body = malformed;
      await expect(client.getNetwork()).rejects.toThrow("coordinator network");
    }

    fetched = 0;
    for (const invalid of [
      { network: "bitcoin" },
      { stormTreeRoot: "not-hex" },
      { tickAssetId: 5 },
    ])
      await expect(
        client.getNetwork(invalid as NetworkVerification),
      ).rejects.toThrow("trusted network values");
    expect(fetched).toBe(0);
  });

  test("waits for a request to finalize and surfaces failure, timeout and abort", async () => {
    const hash = "ab".repeat(32);
    const pending = { status: "pending", payload: null };
    const executed = { status: "executed", payload: "{}" };
    let reads = 0;
    // Answers with each status in turn, then keeps repeating the last.
    const client = (statuses: object[]) => {
      reads = 0;
      return new PriceOracleClient(
        "https://coordinator.test",
        async (request) => {
          expect(String(request)).toBe(
            `https://coordinator.test/users/requests/${hash}`,
          );
          return Response.json(
            statuses[Math.min(reads++, statuses.length - 1)],
          );
        },
      );
    };

    const seen: string[] = [];
    expect(
      await client([
        pending,
        { status: "processing", payload: "{}" },
        { status: "included", payload: "{}" },
        executed,
      ]).waitForTickRequest(hash, {
        intervalMs: 1,
        onStatus: ({ status }) => seen.push(status),
      }),
    ).toEqual(executed);
    expect(seen).toEqual(["pending", "processing", "included", "executed"]);

    await expect(
      client([
        pending,
        { status: "failed", payload: "feed 9 has no price" },
      ]).waitForTickRequest(hash, { intervalMs: 1 }),
    ).rejects.toThrow("feed 9 has no price");
    await expect(
      client([pending]).waitForTickRequest(hash, {
        intervalMs: 1,
        timeoutMs: 20,
      }),
    ).rejects.toThrow("still pending");

    // An abort ends the pause between reads rather than waiting it out.
    const controller = new AbortController();
    const waiting = client([pending]).waitForTickRequest(hash, {
      intervalMs: 60_000,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(new Error("left the page")), 5);
    await expect(waiting).rejects.toThrow("left the page");
    expect(reads).toBe(1);

    await expect(
      client([executed]).waitForTickRequest(hash, {
        signal: AbortSignal.abort(new Error("already gone")),
      }),
    ).rejects.toThrow("already gone");
    expect(reads).toBe(0);

    for (const options of [
      { intervalMs: 0 },
      { timeoutMs: -1 },
      { intervalMs: Number.NaN },
    ])
      await expect(
        client([executed]).waitForTickRequest(hash, options),
      ).rejects.toThrow("positive");
  });

  test("orders a Tick beside a priced request under one signature", () => {
    const feeUtxos = [`${"ab".repeat(32)}:1`];
    const request = createSignedPriceRequest(
      PRIVATE_KEY,
      feeUtxos,
      4,
      undefined,
      { withTick: true },
    );
    const auth = {
      kind: "signature-auth",
      auth_data: publicKeyFromPrivateKey(PRIVATE_KEY),
    };

    expect(request.requests.map(({ kind }) => kind)).toEqual([
      "signed-price-data",
      "tick-utxo",
    ]);
    // Only the priced request names the feed: a Tick naming one is rejected.
    expect(request.requests.map(({ payload }) => JSON.parse(payload))).toEqual([
      { utxo_auth_method: auth, price_feed_id: 4 },
      { utxo_auth_method: auth },
    ]);
    expect(
      schnorr.verify(
        request.header.signature,
        tickRequestSigningHash(request),
        request.header.public_key,
      ),
    ).toBe(true);
    // The signature covers both payloads, so neither can be dropped.
    request.requests.pop();
    expect(
      schnorr.verify(
        request.header.signature,
        tickRequestSigningHash(request),
        request.header.public_key,
      ),
    ).toBe(false);

    expect(
      createSignedPriceRequest(PRIVATE_KEY, feeUtxos, 4).requests,
    ).toHaveLength(1);
  });

  test("checks a confirmed unspent Tick carrying the reported time under the trusted leaf", async () => {
    const time = 1_794_394_600;
    const tick = (timestamp: unknown) => ({
      kind: "tick-utxo",
      vout: 2,
      payload: JSON.stringify({ timestamp }),
    });
    const batch = (results: object[]) => ({
      status: "executed" as const,
      payload: JSON.stringify({ txid: "ab".repeat(32), results }),
    });
    const status = batch([tick(time)]);
    // The amount is the time in satoshis, as Elements reports a Tick.
    const utxo = {
      confirmations: 2,
      asset: ACCOUNT.tick_asset_id,
      value: 17.943946,
      scriptPubKey: { hex: ACCOUNT.tick_script_pubkey },
    };
    const issued = {
      txid: "ab".repeat(32),
      vout: 2,
      asset: ACCOUNT.tick_asset_id,
      timestamp: time,
      scriptPubKey: ACCOUNT.tick_script_pubkey,
    };
    let rpcResult: unknown = utxo;
    let calls = 0;
    const rpc = new ElementsRpcClient({
      url: "http://127.0.0.1:18884",
      fetch: async (_, init) => {
        calls += 1;
        const request = JSON.parse(String(init?.body));
        expect(request.method).toBe("gettxout");
        expect(request.params).toEqual(["ab".repeat(32), 2, true]);
        return Response.json({ result: rpcResult, error: null });
      },
    });

    expect(await verifyExecutedTick(status, ACCOUNT_VERIFICATION, rpc)).toEqual(
      issued,
    );
    // A Tick ordered beside a price is picked out of the batch's results.
    expect(
      await verifyExecutedTick(
        batch([
          { kind: "signed-price-data", vout: 3, payload: "{}" },
          tick(time),
        ]),
        ACCOUNT_VERIFICATION,
        rpc,
      ),
    ).toEqual(issued);

    calls = 0;
    for (const premature of ["pending", "processing", "included"] as const)
      expect(
        await verifyExecutedTick(
          { ...status, status: premature },
          ACCOUNT_VERIFICATION,
          rpc,
        ),
      ).toBeNull();
    expect(calls).toBe(0);

    for (const result of [
      null,
      { ...utxo, confirmations: 0 },
      { ...utxo, asset: "06".repeat(32) },
      { ...utxo, asset: undefined },
      { ...utxo, value: 17.94394601 },
      { ...utxo, value: undefined },
      { ...utxo, scriptPubKey: { hex: ACCOUNT.script_pubkey } },
    ]) {
      rpcResult = result;
      await expect(
        verifyExecutedTick(status, ACCOUNT_VERIFICATION, rpc),
      ).rejects.toThrow("Tick");
    }
    rpcResult = utxo;
    await expect(
      verifyExecutedTick(
        status,
        { ...ACCOUNT_VERIFICATION, tickTapleafHash: "06".repeat(32) },
        rpc,
      ),
    ).rejects.toThrow("Tick");

    for (const malformed of [
      batch([]),
      batch([tick(time), tick(time)]),
      batch([tick(-1)]),
      batch([tick("soon")]),
      batch([{ ...tick(time), vout: -1 }]),
    ])
      await expect(
        verifyExecutedTick(malformed, ACCOUNT_VERIFICATION, rpc),
      ).rejects.toThrow();
    await expect(
      verifyExecutedTick(
        status,
        { ...ACCOUNT_VERIFICATION, tickAssetId: "not-hex" },
        rpc,
      ),
    ).rejects.toThrow("32-byte hex");
  });

  test("names the kind of every coordinator failure and keeps its reason", async () => {
    const failure = async (response: () => Response | Promise<Response>) => {
      const client = new PriceOracleClient("https://coordinator.test", {
        fetch: async () => response(),
        retries: 0,
      });
      const error = await client.getPriceFeeds().catch((error) => error);
      expect(error).toBeInstanceOf(OracleApiError);
      return error as OracleApiError;
    };
    const answered = (status: number, error: string) =>
      failure(() => Response.json({ error }, { status }));

    for (const [status, code] of [
      [400, "invalid_request"],
      [401, "unauthorized"],
      [404, "not_found"],
      [408, "timeout"],
      [409, "conflict"],
      [429, "rate_limited"],
      [500, "server_error"],
      [503, "unavailable"],
    ] as const) {
      const error = await answered(status, "the node's own reason");
      expect([error.code, error.status, error.message]).toEqual([
        code,
        status,
        "the node's own reason",
      ]);
    }
    expect((await answered(503, "this node is not the coordinator")).code).toBe(
      "not_coordinator",
    );

    // A proxy's page is not JSON: the status is reported, not a parse error.
    const gateway = await failure(
      () => new Response("<html>Bad Gateway</html>", { status: 502 }),
    );
    expect([gateway.code, gateway.status, gateway.message]).toEqual([
      "server_error",
      502,
      "HTTP 502",
    ]);
    const empty = await failure(() => new Response("", { status: 200 }));
    expect(empty.code).toBe("invalid_response");

    const cause = new TypeError("fetch failed");
    const unreachable = await failure(() => Promise.reject(cause));
    expect([unreachable.code, unreachable.status, unreachable.message]).toEqual(
      ["network", 0, "fetch failed"],
    );
    expect(unreachable.cause).toBe(cause);
  });

  test("retries a read no node answered, and never a submission", async () => {
    const request = createTickRequest(PRIVATE_KEY, [`${"01".repeat(32)}:0`]);
    let calls = 0;
    // Fails `failures` times in the way given, then answers.
    const client = (
      failures: number,
      fail: () => Response | Promise<Response>,
      options: object = {},
    ) => {
      calls = 0;
      return new PriceOracleClient("https://coordinator.test", {
        fetch: async () =>
          calls++ < failures ? fail() : Response.json({ request_hash: "ok" }),
        retryDelayMs: 1,
        ...options,
      });
    };
    const unreachable = () => Promise.reject(new TypeError("fetch failed"));
    const status = (code: number) => () =>
      Response.json({ error: "busy" }, { status: code });

    for (const fail of [
      unreachable,
      status(408),
      status(429),
      status(500),
      status(502),
      status(503),
      status(504),
    ]) {
      expect(await client(2, fail).getPriceFeeds()).toEqual({
        request_hash: "ok",
      } as never);
      expect(calls).toBe(3);
    }
    // Two retries by default, so a third failure surfaces.
    await expect(client(3, unreachable).getPriceFeeds()).rejects.toThrow(
      "fetch failed",
    );
    expect(calls).toBe(3);
    await expect(
      client(1, unreachable, { retries: 0 }).getPriceFeeds(),
    ).rejects.toThrow("fetch failed");
    expect(calls).toBe(1);

    // What the node decided is not asked again.
    for (const fail of [status(400), status(404), status(409)]) {
      await expect(client(1, fail).getPriceFeeds()).rejects.toThrow("busy");
      expect(calls).toBe(1);
    }
    // A submission that was not answered may still have been queued.
    for (const fail of [unreachable, status(500), status(502)]) {
      await expect(
        client(1, fail).submitTickRequest(request),
      ).rejects.toThrow();
      expect(calls).toBe(1);
    }

    for (const options of [
      { retries: -1 },
      { retries: 1.5 },
      { retryDelayMs: -1 },
    ])
      expect(
        () => new PriceOracleClient("https://coordinator.test", options),
      ).toThrow("retries");
  });

  test("gives a node a limited time to answer, and a wait never outlasts its own limit", async () => {
    const hash = "ab".repeat(32);
    let calls = 0;
    // Takes the request and never answers, heeding the abort or not.
    const silent =
      (heeds: boolean) =>
      (_: string, init?: RequestInit): Promise<Response> => {
        calls++;
        return new Promise((_, reject) => {
          if (heeds)
            init?.signal?.addEventListener("abort", () =>
              reject(init.signal?.reason),
            );
        });
      };

    for (const heeds of [true, false]) {
      calls = 0;
      const oracle = new PriceOracleClient("https://coordinator.test", {
        fetch: silent(heeds),
        timeoutMs: 20,
        retries: 1,
        retryDelayMs: 1,
      });
      const error = await oracle.getPriceFeeds().catch((caught) => caught);
      expect(error).toBeInstanceOf(OracleApiError);
      expect(error).toMatchObject({ code: "timeout", status: 0 });
      expect(error.message).toBe("node did not answer within 20 ms");
      expect(calls).toBe(2);
    }
    // A submission that timed out may have been queued, so it is not resent.
    calls = 0;
    await expect(
      new PriceOracleClient("https://coordinator.test", {
        fetch: silent(false),
        timeoutMs: 20,
      }).submitTickRequest(
        createTickRequest(PRIVATE_KEY, [`${"01".repeat(32)}:0`]),
      ),
    ).rejects.toMatchObject({ code: "timeout" });
    expect(calls).toBe(1);

    // A read that times out on one node is asked of the next.
    const next = new PriceOracleClient(
      ["https://node-1.test", "https://node-2.test"],
      {
        fetch: async (url) =>
          url.startsWith("https://node-1.test")
            ? new Promise<Response>(() => {})
            : Response.json([]),
        timeoutMs: 20,
      },
    );
    expect(await next.getPriceFeeds()).toEqual([]);
    expect(next.nodeUrl).toBe("https://node-2.test");

    // A server error in the middle of a wait is read past.
    let reads = 0;
    const flaky = new PriceOracleClient("https://coordinator.test", {
      fetch: async () =>
        ++reads === 2
          ? Response.json({ error: "internal server error" }, { status: 500 })
          : Response.json(
              reads < 3
                ? { status: "pending", payload: null }
                : { status: "executed", payload: "{}" },
            ),
      retryDelayMs: 1,
    });
    expect(
      await flaky.waitForTickRequest(hash, { intervalMs: 1 }),
    ).toMatchObject({ status: "executed" });

    // The wait's own limit and its abort cut short a read never answered.
    const hung = new PriceOracleClient("https://coordinator.test", {
      fetch: silent(false),
    });
    const started = Date.now();
    await expect(
      hung.waitForTickRequest(hash, { timeoutMs: 30 }),
    ).rejects.toThrow("user request status was not read within 30 ms");
    expect(Date.now() - started).toBeLessThan(1_000);
    const controller = new AbortController();
    setTimeout(() => controller.abort(new Error("left the page")), 10);
    await expect(
      hung.waitForTickRequest(hash, { signal: controller.signal }),
    ).rejects.toThrow("left the page");

    for (const timeoutMs of [0, -1, Number.NaN])
      expect(
        () => new PriceOracleClient("https://coordinator.test", { timeoutMs }),
      ).toThrow("timeoutMs");
  });

  test("finds the coordinator among the nodes it is given and stays with it", async () => {
    const request = createTickRequest(PRIVATE_KEY, [`${"01".repeat(32)}:0`]);
    const asked: string[] = [];
    const notCoordinator = () =>
      Response.json(
        { error: "this node is not the coordinator" },
        { status: 503 },
      );
    // The node at `coordinator` answers; `down` does not answer at all.
    const client = (coordinator: string | null, down: string[] = []) => {
      asked.length = 0;
      return new PriceOracleClient(
        ["https://a.test/", "https://b.test", "https://c.test"],
        {
          fetch: async (url) => {
            const node = new URL(url).origin;
            asked.push(node);
            if (down.includes(node)) throw new TypeError("fetch failed");
            return node === coordinator
              ? Response.json({ request_hash: node })
              : notCoordinator();
          },
          retryDelayMs: 1,
        },
      );
    };

    const oracle = client("https://c.test");
    expect(oracle.nodeUrl).toBe("https://a.test");
    await oracle.getPriceFeeds();
    expect(asked).toEqual([
      "https://a.test",
      "https://b.test",
      "https://c.test",
    ]);
    expect(oracle.nodeUrl).toBe("https://c.test");
    // The next call goes straight to the node that answered.
    asked.length = 0;
    expect(await oracle.submitTickRequest(request)).toEqual({
      request_hash: "https://c.test",
    });
    expect(asked).toEqual(["https://c.test"]);

    // A submission is passed on by a node that refused it, not by a silent one.
    expect(await client("https://b.test").submitTickRequest(request)).toEqual({
      request_hash: "https://b.test",
    });
    await expect(
      client("https://b.test", ["https://a.test"]).submitTickRequest(request),
    ).rejects.toThrow("fetch failed");
    expect(asked).toEqual(["https://a.test"]);
    // A read moves past a node that is down.
    await client("https://b.test", ["https://a.test"]).getPriceFeeds();
    expect(asked).toEqual(["https://a.test", "https://b.test"]);

    // No coordinator among them: said once, after one pass, without retries.
    const none = await client(null)
      .getPriceFeeds()
      .catch((error) => error);
    expect(none.code).toBe("not_coordinator");
    expect(asked).toHaveLength(3);

    expect(() => new PriceOracleClient([])).toThrow("at least one");
    expect(
      () => new PriceOracleClient(["https://a.test", "http://b.test"]),
    ).toThrow("HTTPS");
  });

  test("hands on the reason an Elements node gives for a failed call", async () => {
    const rpc = (response: () => Response) =>
      new ElementsRpcClient({
        url: "http://127.0.0.1:18884",
        fetch: async () => response(),
      });
    const failed = (await rpc(() =>
      Response.json(
        {
          result: null,
          error: {
            code: -5,
            message: "No such mempool or blockchain transaction",
          },
        },
        { status: 500 },
      ),
    )
      .getTransactionConfirmations("ab".repeat(32))
      .catch((error) => error)) as ElementsRpcError;
    expect(failed).toBeInstanceOf(ElementsRpcError);
    expect([failed.message, failed.code, failed.status]).toEqual([
      "No such mempool or blockchain transaction",
      -5,
      500,
    ]);

    const refused = (await rpc(() => new Response("", { status: 401 }))
      .call("getblockcount")
      .catch((error) => error)) as ElementsRpcError;
    expect([refused.message, refused.code, refused.status]).toEqual([
      "Elements RPC returned HTTP 401",
      undefined,
      401,
    ]);
    await expect(
      rpc(() => new Response("not json")).call("getblockcount"),
    ).rejects.toThrow("not JSON");
  });

  test("gives a chain endpoint a limited time to answer", async () => {
    const silent = (): Promise<Response> => new Promise(() => {});
    const esplora = new EsploraClient("https://esplora.test", {
      fetch: silent,
      timeoutMs: 20,
    });
    const elements = new ElementsRpcClient({
      url: "https://rpc.test",
      fetch: silent,
      timeoutMs: 20,
    });

    const late = await esplora
      .getScriptUtxos(ACCOUNT.script_pubkey)
      .catch((error) => error);
    expect(late).toBeInstanceOf(EsploraError);
    expect(late).toMatchObject({
      status: 0,
      message: "Esplora did not answer within 20 ms",
    });
    const rpc = await elements.call("getblockcount").catch((error) => error);
    expect(rpc).toBeInstanceOf(ElementsRpcError);
    expect(rpc).toMatchObject({
      status: 0,
      message: "Elements RPC did not answer within 20 ms",
    });

    for (const timeoutMs of [0, -1, Number.NaN]) {
      expect(
        () => new EsploraClient("https://esplora.test", { timeoutMs }),
      ).toThrow("timeoutMs");
      expect(
        () => new ElementsRpcClient({ url: "https://rpc.test", timeoutMs }),
      ).toThrow("timeoutMs");
    }
  });

  test("reads the same chain facts through Esplora as through Elements RPC", async () => {
    const script = ACCOUNT.script_pubkey;
    const txid = "ab".repeat(32);
    const routes: Record<string, unknown> = {
      [`/scripthash/${bytesToHex(sha256(hexToBytes(script)))}/utxo`]: [
        {
          txid,
          vout: 1,
          value: 100_000,
          asset: "05".repeat(32),
          status: { confirmed: true, block_height: 98 },
        },
        // Unconfirmed, so it cannot pay a request yet, and confidential:
        // no amount to report.
        { txid, vout: 2, value: 7, status: { confirmed: false } },
        { txid, vout: 3, valuecommitment: "08".repeat(33), status: {} },
      ],
      [`/tx/${txid}`]: {
        vout: [
          { scriptpubkey: "6a" },
          { scriptpubkey: script, value: 100_000, asset: "05".repeat(32) },
          { scriptpubkey: script, valuecommitment: "08".repeat(33) },
        ],
        status: { confirmed: true, block_height: 98 },
      },
      [`/tx/${txid}/status`]: { confirmed: true, block_height: 98 },
      [`/tx/${txid}/outspend/1`]: { spent: false },
      [`/tx/${txid}/outspend/2`]: { spent: false },
      "/blocks/tip/height": 100,
    };
    const asked: string[] = [];
    const esplora = new EsploraClient(
      "https://esplora.test/api/",
      async (url, init) => {
        expect(init?.redirect).toBe("error");
        const path = url.replace("https://esplora.test/api", "");
        asked.push(path);
        return path in routes
          ? Response.json(routes[path])
          : new Response("Transaction not found", { status: 404 });
      },
    );

    expect(await esplora.getScriptUtxos(script)).toEqual([
      {
        txid,
        vout: 1,
        scriptPubKey: script,
        amountSats: 100_000,
        asset: "05".repeat(32),
        height: 98,
      },
    ]);

    const explicit: ChainOutput = {
      confirmations: 3,
      scriptPubKey: script,
      asset: "05".repeat(32),
      amountSats: 100_000,
    };
    expect(await esplora.getUnspentOutput(txid, 1)).toEqual(explicit);
    expect(await esplora.getUnspentOutput(txid, 2)).toEqual({
      confirmations: 3,
      scriptPubKey: script,
    });
    expect(await esplora.getTransactionConfirmations(txid)).toBe(3);

    // Spent in a block or in the mempool, and anything short of "not spent".
    for (const outspend of [{ spent: true }, {}, null]) {
      routes[`/tx/${txid}/outspend/1`] = outspend;
      expect(await esplora.getUnspentOutput(txid, 1)).toBeNull();
    }
    routes[`/tx/${txid}/outspend/1`] = { spent: false };
    // No such output, no such transaction.
    expect(await esplora.getUnspentOutput(txid, 9)).toBeNull();
    expect(await esplora.getUnspentOutput("cd".repeat(32), 0)).toBeNull();
    expect(await esplora.getTransactionConfirmations("cd".repeat(32))).toBe(0);

    // Not yet in a block, and a tip that lags behind the transaction.
    routes[`/tx/${txid}`] = {
      ...(routes[`/tx/${txid}`] as object),
      status: { confirmed: false },
    };
    asked.length = 0;
    expect((await esplora.getUnspentOutput(txid, 1))?.confirmations).toBe(0);
    expect(asked).not.toContain("/blocks/tip/height");
    routes[`/tx/${txid}/status`] = { confirmed: true, block_height: 105 };
    expect(await esplora.getTransactionConfirmations(txid)).toBe(0);

    // The same answer as `gettxout` gives for the same output.
    const rpc = new ElementsRpcClient({
      url: "http://127.0.0.1:18884",
      fetch: async () =>
        Response.json({
          result: {
            confirmations: 3,
            asset: "05".repeat(32),
            value: 0.001,
            scriptPubKey: { hex: script },
          },
          error: null,
        }),
    });
    expect(await rpc.getUnspentOutput(txid, 1)).toEqual(explicit);

    const failed = (await new EsploraClient(
      "https://esplora.test",
      async () => new Response("backend is syncing", { status: 503 }),
    )
      .getScriptUtxos(script)
      .catch((error) => error)) as EsploraError;
    expect(failed).toBeInstanceOf(EsploraError);
    expect([failed.status, failed.message]).toEqual([
      503,
      "Esplora returned HTTP 503: backend is syncing",
    ]);
    expect(() => new EsploraClient("http://esplora.test")).toThrow("HTTPS");
    expect(() => new EsploraClient("http://127.0.0.1:3001")).not.toThrow();
    await expect(esplora.getUnspentOutput("xyz", 0)).rejects.toThrow(
      "outpoint",
    );
    await expect(esplora.getUnspentOutput(txid, -1)).rejects.toThrow(
      "outpoint",
    );
  });
});

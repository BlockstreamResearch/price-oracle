import { describe, expect, test } from "bun:test";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import {
  ElementsRpcClient,
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
  type AccountVerification,
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
    "78f352902bd0a539848dad38389f9d5ead152d49bb494b220765bb0ff7ad8c35",
  tickTapleafHash:
    "cb926f0b19654c6513e4bd89f8a354a8ab313c6b190c5541ae3da22e14edd8a8",
};
const ACCOUNT = {
  address: "ert1pnewh9rcdzyqx65srv3cp4pxahxh6yjvvwtaw85fckdekqdm3utts0yqwxr",
  script_pubkey:
    "51209e5d728f0d11006d520364701a84ddb9afa2498c72fae3d138b373603771e2d7",
  storm_eye_asset_id: "01".repeat(32),
  tick_asset_id: "02".repeat(32),
  tick_script_pubkey:
    "5120265faf88d7ee1325f627a1720ecb0d939e135ceab9b928c235cc6f911229e563",
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
        "ex1pnewh9rcdzyqx65srv3cp4pxahxh6yjvvwtaw85fckdekqdm3uttscflvq5",
      ],
      [
        "liquidtestnet",
        "tex1pnewh9rcdzyqx65srv3cp4pxahxh6yjvvwtaw85fckdekqdm3uttsesdt3m",
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
        "b51543ae57064fae1439ed2c355ea46a92e6141716491c439ae31b813c42a71e",
    };
    const expected = {
      ...ACCOUNT,
      tick_script_pubkey:
        "5120d594a98b24b870a07995f993898ef58731d3ee48813f70f26f00e996688e6ab1",
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
});

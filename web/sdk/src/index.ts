import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { bech32m } from "@scure/base";

const REQUEST_TAG = "OracleNetworkV1/NetworkUserRequests";
export const WALLET_REQUEST_SIGNATURE_SCHEME =
  "bitcoin-signed-message-ecdsa-v1";
const PRICE_TAG = "OracleNetworkV1/Price";
const PRICE_VALIDITY_SECONDS = 300n;
const MAX_STORM_TREE_DEPTH = 17;
const HEX_32 = /^[0-9a-f]{64}$/i;
const OUTPOINT = /^[0-9a-f]{64}:[0-9]+$/i;
const UNSPENDABLE_INTERNAL_KEY =
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

export type OracleNetwork = "liquidv1" | "liquidtestnet" | "elementsregtest";

export type OracleAccount = {
  address: string;
  script_pubkey: string;
  storm_eye_asset_id: string;
  tick_asset_id: string;
  tick_script_pubkey: string;
  /** The asset a `signed-price-data` request is issued in. */
  oracle_verifier_asset_id: string;
  network: OracleNetwork;
};

export type AccountVerification = {
  ownerPublicKey: string;
  network: OracleNetwork;
  stormEyeAssetId: string;
  tickAssetId: string;
  verifierAssetId: string;
  /** Independently compiled Account leaf for this owner and Storm Eye asset. */
  accountTapleafHash: string;
  /** Independently compiled voucher leaf for this owner or authentication script. */
  tickTapleafHash: string;
  /** Omit for owner signature authentication; otherwise compile the Tick for this script. */
  authScriptPubKey?: string;
};

export type OracleUtxo = {
  txid: string;
  vout: number;
  scriptPubKey: string;
  amountSats: number;
  asset?: string;
  height?: number;
};

export type TickAuthMethod =
  | { kind: "signature-auth"; auth_data: string }
  | { kind: "asset-id-auth"; auth_data: string }
  | { kind: "scriptPubKey-auth"; auth_data: string };

/** `tick-utxo` issues a Tick; `signed-price-data` an Oracle Verifier. */
export type TickRequestKind = "tick-utxo" | "signed-price-data";

export type TickRequest = {
  header: {
    signature: string;
    public_key: string;
    fee_utxos: string[];
    signature_scheme?: string;
    signing_public_key?: string;
  };
  requests: Array<{ kind: TickRequestKind; payload: string }>;
};

export type TickRequestResult = {
  kind: string | number;
  vout: number;
  auth_method: TickAuthMethod;
  payload: string;
};

export type TickRequestStatus = {
  status: "pending" | "processing" | "included" | "executed" | "failed";
  payload: string | null;
};

export type StormTreeBloom = {
  signature: string;
  branch: string;
  proof: Array<{ right: boolean; hash: string }>;
};

/** The payload of an executed `signed-price-data` request. */
export type SignedPriceData = {
  price_data: string;
  storm_tree_bloom: StormTreeBloom;
};

export type PriceFeedData = {
  feedId: number;
  decimals: number;
  price: bigint;
  receivedAt: bigint;
  validUntil: bigint;
};

export type SignedPriceVerification = {
  /** Current Storm Eye root from an independently trusted source, not this response. */
  stormTreeRoot: string;
  feedId: number;
  decimals: number;
  /** Trusted Unix time in seconds. */
  now: bigint;
};

export type IssuedPriceVerification = SignedPriceVerification & {
  /** Verifier asset ID from independently verified network issuance. */
  verifierAssetId: string;
  /** Locally compiled voucher leaf for the requested authentication method. */
  verifierTapleafHash: string;
};

export type PriceFeedInfo = {
  id: number;
  symbol: string;
  decimals: number;
  base: string;
  quote: string;
  kind: string;
};
export type PriceFeedRate = {
  main: {
    feed: {
      feed_id: number;
      decimals: number;
      price: number;
      received_at: number;
      valid_until: number;
    };
    signature: string;
    public_key: string;
  };
};

export type IssuedTick = {
  txid: string;
  vout: number;
  asset: string;
  timestamp: number;
  scriptPubKey: string;
};

export type PredictionResolution = {
  predictionId: string;
  occurredAt: number;
  signature: string;
};

export type TickSpendPlan = {
  inputs: {
    predictionPosition: 0;
    tick: 1;
  };
  outputs: {
    payout: 0;
    tickBurn: 1;
  };
  tickBurnOutput: {
    asset: string;
    amount: number;
    scriptPubKey: "6a";
  };
  tickWitness: {
    path: "signature-auth";
    burnOutputIndex: 1;
    signatureMessage: "sig_all_hash";
  };
  predictionWitness: {
    predictionId: string;
    occurredAt: number;
    adminSignature: string;
    tickInputIndex: 1;
    payoutOutputIndex: 0;
  };
};

export type RpcOptions = {
  url: string;
  username?: string;
  password?: string;
  fetch?: typeof globalThis.fetch;
};

export class ElementsRpcClient {
  readonly #options: RpcOptions;
  #requestId = 0;

  constructor(options: RpcOptions) {
    this.#options = options;
  }

  async call<Result>(method: string, params: unknown[] = []): Promise<Result> {
    const headers = new Headers({ "content-type": "application/json" });
    if (this.#options.username !== undefined) {
      const credentials = `${this.#options.username}:${this.#options.password ?? ""}`;
      headers.set("authorization", `Basic ${btoa(credentials)}`);
    }
    const fetcher = this.#options.fetch ?? globalThis.fetch;
    const response = await fetcher(this.#options.url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: ++this.#requestId,
        method,
        params,
      }),
    });
    if (!response.ok) {
      throw new Error(`Elements RPC returned HTTP ${response.status}`);
    }
    const body = (await response.json()) as {
      result: Result;
      error: { message: string } | null;
    };
    if (body.error) {
      throw new Error(body.error.message);
    }
    return body.result;
  }

  async getScriptUtxos(scriptPubKey: string): Promise<OracleUtxo[]> {
    assertHex(scriptPubKey, "scriptPubKey");
    const result = await this.call<{
      unspents: Array<{
        txid: string;
        vout: number;
        scriptPubKey: string;
        amount: number;
        asset?: string;
        height?: number;
      }>;
    }>("scantxoutset", ["start", [{ desc: `raw(${scriptPubKey})` }]]);

    return result.unspents.map((utxo) => ({
      txid: utxo.txid,
      vout: utxo.vout,
      scriptPubKey: utxo.scriptPubKey,
      amountSats: Math.round(utxo.amount * 100_000_000),
      ...(utxo.asset === undefined ? {} : { asset: utxo.asset }),
      ...(utxo.height === undefined ? {} : { height: utxo.height }),
    }));
  }

  async getTransactionConfirmations(txid: string): Promise<number> {
    if (!HEX_32.test(txid)) {
      throw new Error("txid must be 32-byte hex");
    }
    const transaction = await this.call<{ confirmations?: number }>(
      "getrawtransaction",
      [txid, true],
    );

    return transaction.confirmations ?? 0;
  }

  broadcast(transactionHex: string, maxBurnSats = 0): Promise<string> {
    assertHex(transactionHex, "transaction");
    if (!Number.isSafeInteger(maxBurnSats) || maxBurnSats < 0) {
      throw new Error("maxBurnSats must be a non-negative safe integer");
    }
    const params: unknown[] = [transactionHex];
    if (maxBurnSats > 0) {
      params.push(0.1, maxBurnSats / 100_000_000);
    }
    return this.call<string>("sendrawtransaction", params);
  }
}

export class PriceOracleClient {
  readonly #coordinatorUrl: string;
  readonly #fetch: typeof globalThis.fetch;

  constructor(coordinatorUrl: string, fetcher = globalThis.fetch) {
    const url = new URL(coordinatorUrl);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
      throw new Error("coordinator URL must use HTTPS (HTTP is loopback-only)");
    this.#coordinatorUrl = coordinatorUrl.replace(/\/$/, "");
    this.#fetch = fetcher.bind(globalThis);
  }

  async getAccount(
    publicKey: string,
    verification: AccountVerification,
  ): Promise<OracleAccount> {
    assertXOnlyPublicKey(publicKey);
    const expected = deriveAccount(verification);
    if (publicKey.toLowerCase() !== verification.ownerPublicKey.toLowerCase())
      throw new Error(
        "Account verification owner does not match the requested public key",
      );

    const authScriptPubKey = verification.authScriptPubKey;
    const account = await this.#json<OracleAccount>(
      `/users/account/${publicKey.toLowerCase()}${authScriptPubKey === undefined ? "" : `?auth_script_pubkey=${encodeURIComponent(authScriptPubKey)}`}`,
    );

    for (const [field, value] of Object.entries(expected)) {
      const received = account?.[field as keyof OracleAccount];
      if (
        typeof received !== "string" ||
        (field === "address" || field === "network"
          ? received
          : received.toLowerCase()) !== value
      )
        throw new Error(
          `coordinator Account ${field} does not match the trusted derivation`,
        );
    }

    return expected;
  }

  async submitTickRequest(
    request: TickRequest,
  ): Promise<{ request_hash: string }> {
    return this.#json("/users/requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
  }

  getTickRequest(requestHash: string): Promise<TickRequestStatus> {
    if (!HEX_32.test(requestHash)) {
      throw new Error("request hash must be 32-byte hex");
    }
    return this.#json(`/users/requests/${requestHash}`);
  }

  getPriceFeeds(): Promise<PriceFeedInfo[]> {
    return this.#json("/price-feeds");
  }

  getPriceFeed(feedId: number): Promise<PriceFeedRate> {
    assertFeedId(feedId);
    return this.#json(`/price-feeds/${feedId}`);
  }

  async #json<Result>(path: string, init?: RequestInit): Promise<Result> {
    const response = await this.#fetch(`${this.#coordinatorUrl}${path}`, {
      ...init,
      redirect: "error",
    });
    const body = (await response.json()) as Result | { error: string };
    if (!response.ok) {
      throw new Error(
        "error" in (body as object)
          ? (body as { error: string }).error
          : `HTTP ${response.status}`,
      );
    }
    return body as Result;
  }
}

/** Derive an Account and Tick from independently trusted contract leaves and asset IDs. */
export function deriveAccount(
  verification: AccountVerification,
): OracleAccount {
  if (!verification || typeof verification !== "object")
    throw new Error("trusted Account verification context is required");
  assertXOnlyPublicKey(verification.ownerPublicKey);
  if (
    !["liquidv1", "liquidtestnet", "elementsregtest"].includes(
      verification.network,
    )
  )
    throw new Error("unsupported trusted Account network");
  if (
    [
      verification.stormEyeAssetId,
      verification.tickAssetId,
      verification.verifierAssetId,
      verification.accountTapleafHash,
      verification.tickTapleafHash,
    ].some((value) => typeof value !== "string" || !HEX_32.test(value))
  )
    throw new Error(
      "trusted Account assets and tapleaf hashes must be 32-byte hex",
    );
  if (verification.authScriptPubKey !== undefined)
    validateAuthMethod({
      kind: "scriptPubKey-auth",
      auth_data: verification.authScriptPubKey,
    });

  const scriptPubKey = elementsTaprootScript(
    UNSPENDABLE_INTERNAL_KEY,
    verification.accountTapleafHash,
  );
  const tickScriptPubKey = elementsTaprootScript(
    UNSPENDABLE_INTERNAL_KEY,
    verification.tickTapleafHash,
  );
  const prefix = {
    liquidv1: "ex",
    liquidtestnet: "tex",
    elementsregtest: "ert",
  }[verification.network];
  const address = bech32m.encode(prefix, [
    1,
    ...bech32m.toWords(hexToBytes(scriptPubKey.slice(4))),
  ]);

  return {
    address,
    script_pubkey: scriptPubKey,
    storm_eye_asset_id: verification.stormEyeAssetId.toLowerCase(),
    tick_asset_id: verification.tickAssetId.toLowerCase(),
    tick_script_pubkey: tickScriptPubKey,
    oracle_verifier_asset_id: verification.verifierAssetId.toLowerCase(),
    network: verification.network,
  };
}

export function publicKeyFromPrivateKey(privateKey: string): string {
  assertPrivateKey(privateKey);
  return bytesToHex(schnorr.getPublicKey(privateKey));
}

export function signSchnorrDigest(privateKey: string, digest: string): string {
  assertPrivateKey(privateKey);
  if (!HEX_32.test(digest)) {
    throw new Error("digest must be 32-byte hex");
  }

  return bytesToHex(schnorr.sign(hexToBytes(digest), privateKey));
}

export function createWalletTickRequest(
  compressedPublicKey: string,
  feeUtxos: string[],
  authScriptPubKey: string,
): TickRequest {
  if (!/^(02|03)[0-9a-f]{64}$/i.test(compressedPublicKey))
    throw new Error("wallet public key must be compressed secp256k1 hex");
  secp256k1.ProjectivePoint.fromHex(compressedPublicKey);
  if (
    feeUtxos.length === 0 ||
    feeUtxos.some((outpoint) => !OUTPOINT.test(outpoint))
  )
    throw new Error("fee UTXOs must contain txid:vout outpoints");
  const authMethod: TickAuthMethod = {
    kind: "scriptPubKey-auth",
    auth_data: authScriptPubKey,
  };
  validateAuthMethod(authMethod);
  return {
    header: {
      signature: "",
      public_key: compressedPublicKey.slice(2).toLowerCase(),
      fee_utxos: [...feeUtxos],
      signature_scheme: WALLET_REQUEST_SIGNATURE_SCHEME,
      signing_public_key: compressedPublicKey.toLowerCase(),
    },
    requests: [
      {
        kind: "tick-utxo",
        payload: JSON.stringify({ utxo_auth_method: authMethod }),
      },
    ],
  };
}

export function walletRequestSigningMessage(request: TickRequest): string {
  if (
    request.header.signature_scheme !== WALLET_REQUEST_SIGNATURE_SCHEME ||
    !request.header.signing_public_key
  ) {
    throw new Error("request must use wallet message authorization");
  }
  return `${REQUEST_TAG}\n${WALLET_REQUEST_SIGNATURE_SCHEME}\n${JSON.stringify([
    request.header.public_key,
    request.header.signing_public_key,
    request.header.fee_utxos,
    request.requests,
  ])}`;
}

function assertFeedId(feedId: number): void {
  if (!Number.isInteger(feedId) || feedId < 0 || feedId > 0xffffffff) {
    throw new Error("price feed id must be an unsigned 32-bit integer");
  }
}

export function createWalletSignedPriceRequest(
  compressedPublicKey: string,
  feeUtxos: string[],
  authScriptPubKey: string,
  priceFeedId: number,
  options: { withTick?: boolean } = {},
): TickRequest {
  assertFeedId(priceFeedId);
  const request = createWalletTickRequest(
    compressedPublicKey,
    feeUtxos,
    authScriptPubKey,
  );
  const tick = request.requests[0];
  if (!tick) throw new Error("wallet request has no Tick template");
  request.requests = [
    {
      kind: "signed-price-data",
      payload: JSON.stringify({
        ...JSON.parse(tick.payload),
        price_feed_id: priceFeedId,
      }),
    },
  ];
  if (options.withTick) request.requests.push(tick);
  return request;
}

export function createTickRequest(
  privateKey: string,
  feeUtxos: string[],
  authMethod?: TickAuthMethod,
): TickRequest {
  return buildRequest(privateKey, feeUtxos, "tick-utxo", authMethod);
}

/**
 * A priced request: issues an Oracle Verifier and returns the signed rate,
 * checked by {@link verifySignedPriceData}.
 */
export function createSignedPriceRequest(
  privateKey: string,
  feeUtxos: string[],
  priceFeedId: number,
  authMethod?: TickAuthMethod,
): TickRequest {
  if (
    !Number.isInteger(priceFeedId) ||
    priceFeedId < 0 ||
    priceFeedId > 0xffffffff
  ) {
    throw new Error("price feed id must be an unsigned 32-bit integer");
  }
  return buildRequest(
    privateKey,
    feeUtxos,
    "signed-price-data",
    authMethod,
    priceFeedId,
  );
}

function buildRequest(
  privateKey: string,
  feeUtxos: string[],
  kind: TickRequestKind,
  authMethod: TickAuthMethod | undefined,
  priceFeedId?: number,
): TickRequest {
  assertPrivateKey(privateKey);
  if (
    feeUtxos.length === 0 ||
    feeUtxos.some((outpoint) => !OUTPOINT.test(outpoint))
  ) {
    throw new Error("fee UTXOs must contain txid:vout outpoints");
  }
  const publicKey = publicKeyFromPrivateKey(privateKey);
  const selectedAuth = authMethod ?? {
    kind: "signature-auth",
    auth_data: publicKey,
  };
  validateAuthMethod(selectedAuth);
  // The network rejects a payload carrying any field it does not know, and a
  // plain Tick must name no feed at all, so the key is present only for a
  // priced request and spelled as the specification spells it.
  const payload = JSON.stringify(
    priceFeedId === undefined
      ? { utxo_auth_method: selectedAuth }
      : { utxo_auth_method: selectedAuth, price_feed_id: priceFeedId },
  );
  const request: TickRequest = {
    header: {
      signature: "",
      public_key: publicKey,
      fee_utxos: [...feeUtxos],
    },
    requests: [{ kind, payload }],
  };
  request.header.signature = bytesToHex(
    schnorr.sign(tickRequestSigningHash(request), privateKey),
  );
  return request;
}

export function tickRequestSigningHash(request: TickRequest): Uint8Array {
  const message =
    request.requests.map(({ payload }) => payload).join("") +
    request.header.fee_utxos.join("");
  const tagHash = sha256(utf8ToBytes(REQUEST_TAG));
  return sha256(
    new Uint8Array([...tagHash, ...tagHash, ...utf8ToBytes(message)]),
  );
}

/** The 32 canonical bytes the network signs, as the numbers they encode. */
export function decodePriceData(priceData: string): PriceFeedData {
  if (!HEX_32.test(priceData)) {
    throw new Error("price data must be 32-byte hex");
  }
  const bytes = hexToBytes(priceData);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  return {
    feedId: view.getUint32(0),
    decimals: view.getUint32(4),
    price: view.getBigUint64(8),
    receivedAt: view.getBigUint64(16),
    validUntil: view.getBigUint64(24),
  };
}

/**
 * Authenticate a fresh rate against the caller's trusted current Storm Eye root.
 * This does not establish issuance, confirmation, or unspentness of a Verifier.
 */
export function verifySignedPriceData(
  details: SignedPriceData,
  verification: SignedPriceVerification,
): boolean {
  try {
    if (!HEX_32.test(verification.stormTreeRoot)) return false;
    assertFeedId(verification.feedId);
    assertFeedId(verification.decimals);
    if (typeof verification.now !== "bigint" || verification.now < 0n)
      return false;

    const price = decodePriceData(details.price_data);
    if (
      price.feedId !== verification.feedId ||
      price.decimals !== verification.decimals ||
      price.receivedAt > verification.now ||
      price.validUntil <= verification.now ||
      price.validUntil <= price.receivedAt ||
      price.validUntil - price.receivedAt > PRICE_VALIDITY_SECONDS
    )
      return false;

    const { signature, branch, proof } = details.storm_tree_bloom;
    if (
      !HEX_32.test(branch) ||
      !/^[0-9a-f]{128}$/i.test(signature) ||
      !Array.isArray(proof) ||
      proof.length < 1 ||
      proof.length > MAX_STORM_TREE_DEPTH
    )
      return false;

    let root = sha256(new Uint8Array([...hexToBytes(branch), 0x01]));
    for (const sibling of proof) {
      if (typeof sibling.right !== "boolean" || !HEX_32.test(sibling.hash))
        return false;
      const hash = hexToBytes(sibling.hash);
      root = sha256(
        new Uint8Array(sibling.right ? [...hash, ...root] : [...root, ...hash]),
      );
    }
    if (bytesToHex(root) !== verification.stormTreeRoot.toLowerCase())
      return false;

    const tagHash = sha256(utf8ToBytes(PRICE_TAG));
    const message = sha256(
      new Uint8Array([
        ...tagHash,
        ...tagHash,
        ...hexToBytes(details.price_data),
      ]),
    );

    return schnorr.verify(hexToBytes(signature), message, hexToBytes(branch));
  } catch {
    return false;
  }
}

export function parseExecutedTick(
  status: TickRequestStatus,
): { txid: string; results: TickRequestResult[] } | null {
  if (
    status.payload === null ||
    (status.status !== "processing" &&
      status.status !== "included" &&
      status.status !== "executed")
  ) {
    return null;
  }
  return JSON.parse(status.payload) as {
    txid: string;
    results: TickRequestResult[];
  };
}

/** Authenticate an executed response; its returned outpoint is not chain-verified. */
export function parseExecutedSignedPrice(
  status: TickRequestStatus,
  verification: SignedPriceVerification,
): { txid: string; verifierVout: number; signedPrice: SignedPriceData } | null {
  if (status.status !== "executed") return null;
  const executed = parseExecutedTick(status);
  if (!executed) return null;
  if (!HEX_32.test(executed.txid) || !Array.isArray(executed.results))
    throw new Error("invalid issuance result");
  const results = executed.results.filter(
    (result) => result.kind === "signed-price-data",
  );
  if (results.length !== 1)
    throw new Error("expected exactly one issued Verifier");
  const result = results[0];
  if (!result) throw new Error("issuance result has no Verifier");
  if (
    !Number.isInteger(result.vout) ||
    result.vout < 0 ||
    result.vout > 0xffffffff
  )
    throw new Error("invalid Verifier output index");
  const signedPrice = JSON.parse(result.payload) as SignedPriceData;
  decodePriceData(signedPrice.price_data);
  if (!verifySignedPriceData(signedPrice, verification))
    throw new Error("oracle price does not verify against the trusted context");
  return { txid: executed.txid, verifierVout: result.vout, signedPrice };
}

/** Check a finalized price and its confirmed, unspent Verifier via independent RPC. */
export async function verifyExecutedSignedPrice(
  status: TickRequestStatus,
  verification: IssuedPriceVerification,
  elements: ElementsRpcClient,
): Promise<ReturnType<typeof parseExecutedSignedPrice>> {
  if (
    !HEX_32.test(verification.verifierAssetId) ||
    !HEX_32.test(verification.verifierTapleafHash)
  )
    throw new Error(
      "trusted Verifier asset and tapleaf hash must be 32-byte hex",
    );
  const executed = parseExecutedSignedPrice(status, verification);
  if (!executed) return null;

  const branch = executed.signedPrice.storm_tree_bloom.branch;
  const scriptPubKey = elementsTaprootScript(
    branch,
    verification.verifierTapleafHash,
  );

  const utxo = await elements.call<{
    confirmations: number;
    asset?: string;
    value?: number;
    scriptPubKey: { hex: string };
  } | null>("gettxout", [executed.txid, executed.verifierVout, true]);
  if (
    !utxo ||
    !Number.isSafeInteger(utxo.confirmations) ||
    utxo.confirmations < 1 ||
    utxo.asset?.toLowerCase() !== verification.verifierAssetId.toLowerCase() ||
    utxo.value !== 0.00000001 ||
    utxo.scriptPubKey.hex.toLowerCase() !== scriptPubKey
  )
    throw new Error(
      "confirmed unspent Verifier does not match the trusted context",
    );

  return executed;
}

function elementsTaprootScript(
  internalPublicKey: string,
  tapleafHash: string,
): string {
  const tagHash = sha256(utf8ToBytes("TapTweak/elements"));
  const tweakHash = sha256(
    new Uint8Array([
      ...tagHash,
      ...tagHash,
      ...hexToBytes(internalPublicKey),
      ...hexToBytes(tapleafHash),
    ]),
  );
  const tweak = BigInt(`0x${bytesToHex(tweakHash)}`);
  if (tweak >= secp256k1.CURVE.n)
    throw new Error("invalid Elements Taproot tweak");

  const internalKey = secp256k1.ProjectivePoint.fromHex(
    `02${internalPublicKey}`,
  );
  const outputKey =
    tweak === 0n
      ? internalKey
      : internalKey.add(secp256k1.ProjectivePoint.BASE.multiply(tweak));
  return `5120${bytesToHex(outputKey.toRawBytes(true).slice(1))}`;
}

export function createTickSpendPlan(
  tick: IssuedTick,
  resolution: PredictionResolution,
): TickSpendPlan {
  if (!HEX_32.test(resolution.predictionId)) {
    throw new Error("prediction id must be 32-byte hex");
  }
  if (!/^[0-9a-f]{128}$/i.test(resolution.signature)) {
    throw new Error("admin signature must be 64-byte hex");
  }
  if (
    !Number.isSafeInteger(tick.timestamp) ||
    tick.timestamp < resolution.occurredAt
  ) {
    throw new Error(
      "Tick timestamp must be at or after the signed occurrence time",
    );
  }
  assertHex(tick.asset, "Tick asset");

  return {
    inputs: { predictionPosition: 0, tick: 1 },
    outputs: { payout: 0, tickBurn: 1 },
    tickBurnOutput: {
      asset: tick.asset,
      amount: tick.timestamp,
      scriptPubKey: "6a",
    },
    tickWitness: {
      path: "signature-auth",
      burnOutputIndex: 1,
      signatureMessage: "sig_all_hash",
    },
    predictionWitness: {
      predictionId: resolution.predictionId.toLowerCase(),
      occurredAt: resolution.occurredAt,
      adminSignature: resolution.signature.toLowerCase(),
      tickInputIndex: 1,
      payoutOutputIndex: 0,
    },
  };
}

function validateAuthMethod(method: TickAuthMethod): void {
  if (method.kind === "scriptPubKey-auth") {
    assertHex(method.auth_data, "authentication scriptPubKey");
    return;
  }
  if (!HEX_32.test(method.auth_data)) {
    throw new Error(`${method.kind} auth data must be 32-byte hex`);
  }
}

function assertPrivateKey(privateKey: string): void {
  if (!HEX_32.test(privateKey)) {
    throw new Error("private key must be 32-byte hex");
  }
  schnorr.getPublicKey(hexToBytes(privateKey));
}

function assertXOnlyPublicKey(publicKey: string): void {
  if (!HEX_32.test(publicKey)) {
    throw new Error("public key must be 32-byte x-only hex");
  }
  schnorr.utils.lift_x(BigInt(`0x${publicKey}`));
}

function assertHex(value: string, name: string): void {
  if (
    value.length === 0 ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]+$/i.test(value)
  ) {
    throw new Error(`${name} must be hex`);
  }
}

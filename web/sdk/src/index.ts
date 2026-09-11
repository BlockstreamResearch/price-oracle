import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

const REQUEST_TAG = "OracleNetworkV1/NetworkUserRequests";
const HEX_32 = /^[0-9a-f]{64}$/i;
const OUTPOINT = /^[0-9a-f]{64}:[0-9]+$/i;

export type OracleNetwork = "liquidv1" | "liquidtestnet" | "elementsregtest";

export type OracleAccount = {
  address: string;
  script_pubkey: string;
  storm_eye_asset_id: string;
  tick_asset_id: string;
  tick_script_pubkey: string;
  network: OracleNetwork;
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

export type TickRequest = {
  header: {
    signature: string;
    public_key: string;
    fee_utxos: string[];
  };
  requests: Array<{ kind: "tick-utxo"; payload: string }>;
};

export type TickRequestResult = {
  kind: string | number;
  vout: number;
  auth_method: TickAuthMethod;
  payload: string;
};

export type TickRequestStatus = {
  status: "pending" | "processing" | "executed" | "failed";
  payload: string | null;
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
    this.#coordinatorUrl = coordinatorUrl.replace(/\/$/, "");
    this.#fetch = fetcher.bind(globalThis);
  }

  async getAccount(publicKey: string): Promise<OracleAccount> {
    assertXOnlyPublicKey(publicKey);
    return this.#json<OracleAccount>(
      `/users/account/${publicKey.toLowerCase()}`,
    );
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

  async #json<Result>(path: string, init?: RequestInit): Promise<Result> {
    const response = await this.#fetch(`${this.#coordinatorUrl}${path}`, init);
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

export function createTickRequest(
  privateKey: string,
  feeUtxos: string[],
  authMethod?: TickAuthMethod,
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
  const payload = JSON.stringify({ utxo_auth_method: selectedAuth });
  const request: TickRequest = {
    header: {
      signature: "",
      public_key: publicKey,
      fee_utxos: [...feeUtxos],
    },
    requests: [{ kind: "tick-utxo", payload }],
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

export function parseExecutedTick(
  status: TickRequestStatus,
): { txid: string; results: TickRequestResult[] } | null {
  if (
    status.payload === null ||
    (status.status !== "processing" && status.status !== "executed")
  ) {
    return null;
  }
  return JSON.parse(status.payload) as {
    txid: string;
    results: TickRequestResult[];
  };
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

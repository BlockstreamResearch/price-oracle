import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
const REQUEST_TAG = "OracleNetworkV1/NetworkUserRequests";
const HEX_32 = /^[0-9a-f]{64}$/i;
const OUTPOINT = /^[0-9a-f]{64}:[0-9]+$/i;
export class ElementsRpcClient {
    #options;
    #requestId = 0;
    constructor(options) {
        this.#options = options;
    }
    async call(method, params = []) {
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
        const body = (await response.json());
        if (body.error) {
            throw new Error(body.error.message);
        }
        return body.result;
    }
    async getScriptUtxos(scriptPubKey) {
        assertHex(scriptPubKey, "scriptPubKey");
        const result = await this.call("scantxoutset", ["start", [{ desc: `raw(${scriptPubKey})` }]]);
        return result.unspents.map((utxo) => ({
            txid: utxo.txid,
            vout: utxo.vout,
            scriptPubKey: utxo.scriptPubKey,
            amountSats: Math.round(utxo.amount * 100_000_000),
            ...(utxo.asset === undefined ? {} : { asset: utxo.asset }),
            ...(utxo.height === undefined ? {} : { height: utxo.height }),
        }));
    }
    async getTransactionConfirmations(txid) {
        if (!HEX_32.test(txid)) {
            throw new Error("txid must be 32-byte hex");
        }
        const transaction = await this.call("getrawtransaction", [txid, true]);
        return transaction.confirmations ?? 0;
    }
    broadcast(transactionHex, maxBurnSats = 0) {
        assertHex(transactionHex, "transaction");
        if (!Number.isSafeInteger(maxBurnSats) || maxBurnSats < 0) {
            throw new Error("maxBurnSats must be a non-negative safe integer");
        }
        const params = [transactionHex];
        if (maxBurnSats > 0) {
            params.push(0.1, maxBurnSats / 100_000_000);
        }
        return this.call("sendrawtransaction", params);
    }
}
export class PriceOracleClient {
    #coordinatorUrl;
    #fetch;
    constructor(coordinatorUrl, fetcher = globalThis.fetch) {
        this.#coordinatorUrl = coordinatorUrl.replace(/\/$/, "");
        this.#fetch = fetcher.bind(globalThis);
    }
    async getAccount(publicKey) {
        assertXOnlyPublicKey(publicKey);
        return this.#json(`/users/account/${publicKey.toLowerCase()}`);
    }
    async submitTickRequest(request) {
        return this.#json("/users/requests", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(request),
        });
    }
    getTickRequest(requestHash) {
        if (!HEX_32.test(requestHash)) {
            throw new Error("request hash must be 32-byte hex");
        }
        return this.#json(`/users/requests/${requestHash}`);
    }
    async #json(path, init) {
        const response = await this.#fetch(`${this.#coordinatorUrl}${path}`, init);
        const body = (await response.json());
        if (!response.ok) {
            throw new Error("error" in body
                ? body.error
                : `HTTP ${response.status}`);
        }
        return body;
    }
}
export function publicKeyFromPrivateKey(privateKey) {
    assertPrivateKey(privateKey);
    return bytesToHex(schnorr.getPublicKey(privateKey));
}
export function signSchnorrDigest(privateKey, digest) {
    assertPrivateKey(privateKey);
    if (!HEX_32.test(digest)) {
        throw new Error("digest must be 32-byte hex");
    }
    return bytesToHex(schnorr.sign(hexToBytes(digest), privateKey));
}
export function createTickRequest(privateKey, feeUtxos, authMethod) {
    assertPrivateKey(privateKey);
    if (feeUtxos.length === 0 ||
        feeUtxos.some((outpoint) => !OUTPOINT.test(outpoint))) {
        throw new Error("fee UTXOs must contain txid:vout outpoints");
    }
    const publicKey = publicKeyFromPrivateKey(privateKey);
    const selectedAuth = authMethod ?? {
        kind: "signature-auth",
        auth_data: publicKey,
    };
    validateAuthMethod(selectedAuth);
    const payload = JSON.stringify({ utxo_auth_method: selectedAuth });
    const request = {
        header: {
            signature: "",
            public_key: publicKey,
            fee_utxos: [...feeUtxos],
        },
        requests: [{ kind: "tick-utxo", payload }],
    };
    request.header.signature = bytesToHex(schnorr.sign(tickRequestSigningHash(request), privateKey));
    return request;
}
export function tickRequestSigningHash(request) {
    const message = request.requests.map(({ payload }) => payload).join("") +
        request.header.fee_utxos.join("");
    const tagHash = sha256(utf8ToBytes(REQUEST_TAG));
    return sha256(new Uint8Array([...tagHash, ...tagHash, ...utf8ToBytes(message)]));
}
export function parseExecutedTick(status) {
    if (status.payload === null ||
        (status.status !== "processing" && status.status !== "executed")) {
        return null;
    }
    return JSON.parse(status.payload);
}
export function createTickSpendPlan(tick, resolution) {
    if (!HEX_32.test(resolution.predictionId)) {
        throw new Error("prediction id must be 32-byte hex");
    }
    if (!/^[0-9a-f]{128}$/i.test(resolution.signature)) {
        throw new Error("admin signature must be 64-byte hex");
    }
    if (!Number.isSafeInteger(tick.timestamp) ||
        tick.timestamp < resolution.occurredAt) {
        throw new Error("Tick timestamp must be at or after the signed occurrence time");
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
function validateAuthMethod(method) {
    if (method.kind === "scriptPubKey-auth") {
        assertHex(method.auth_data, "authentication scriptPubKey");
        return;
    }
    if (!HEX_32.test(method.auth_data)) {
        throw new Error(`${method.kind} auth data must be 32-byte hex`);
    }
}
function assertPrivateKey(privateKey) {
    if (!HEX_32.test(privateKey)) {
        throw new Error("private key must be 32-byte hex");
    }
    schnorr.getPublicKey(hexToBytes(privateKey));
}
function assertXOnlyPublicKey(publicKey) {
    if (!HEX_32.test(publicKey)) {
        throw new Error("public key must be 32-byte x-only hex");
    }
    schnorr.utils.lift_x(BigInt(`0x${publicKey}`));
}
function assertHex(value, name) {
    if (value.length === 0 ||
        value.length % 2 !== 0 ||
        !/^[0-9a-f]+$/i.test(value)) {
        throw new Error(`${name} must be hex`);
    }
}

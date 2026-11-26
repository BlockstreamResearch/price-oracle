import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { bech32m } from "@scure/base";
const REQUEST_TAG = "OracleNetworkV1/NetworkUserRequests";
export const WALLET_REQUEST_SIGNATURE_SCHEME = "bitcoin-signed-message-ecdsa-v1";
const PRICE_TAG = "OracleNetworkV1/Price";
const PRICE_VALIDITY_SECONDS = 300n;
const MAX_STORM_TREE_DEPTH = 17;
const HEX_32 = /^[0-9a-f]{64}$/i;
const OUTPOINT = /^[0-9a-f]{64}:[0-9]+$/i;
const UNSPENDABLE_INTERNAL_KEY = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const NETWORKS = [
    "liquidv1",
    "liquidtestnet",
    "elementsregtest",
];
const NOT_COORDINATOR = "this node is not the coordinator";
/** A node answer that is not a success, or no answer at all. */
export class OracleApiError extends Error {
    code;
    /** The HTTP status; 0 when the node did not answer. */
    status;
    constructor(message, code, status, options) {
        super(message, options);
        this.name = "OracleApiError";
        this.code = code;
        this.status = status;
    }
}
/** An Elements RPC failure, with the node's own message when it sent one. */
export class ElementsRpcError extends Error {
    status;
    /** The JSON-RPC error code, such as -5 for an unknown transaction. */
    code;
    constructor(message, status, code) {
        super(message);
        this.name = "ElementsRpcError";
        this.status = status;
        this.code = code;
    }
}
/** An Esplora answer that is not a success. */
export class EsploraError extends Error {
    status;
    constructor(message, status) {
        super(message);
        this.name = "EsploraError";
        this.status = status;
    }
}
export class ElementsRpcClient {
    #options;
    #requestId = 0;
    constructor(options) {
        if (options.timeoutMs !== undefined && !(options.timeoutMs > 0))
            throw new Error("timeoutMs must be positive milliseconds");
        this.#options = options;
    }
    async call(method, params = []) {
        const headers = new Headers({ "content-type": "application/json" });
        if (this.#options.username !== undefined) {
            const credentials = `${this.#options.username}:${this.#options.password ?? ""}`;
            headers.set("authorization", `Basic ${btoa(credentials)}`);
        }
        const fetcher = this.#options.fetch ?? globalThis.fetch;
        const timeoutMs = this.#options.timeoutMs ?? 15_000;
        let response;
        let text;
        try {
            ({ response, text } = await fetchText(fetcher, this.#options.url, {
                method: "POST",
                headers,
                body: JSON.stringify({
                    jsonrpc: "2.0",
                    id: ++this.#requestId,
                    method,
                    params,
                }),
            }, timeoutMs));
        }
        catch (error) {
            if (error instanceof RequestTimeout)
                throw new ElementsRpcError(`Elements RPC did not answer within ${timeoutMs} ms`, 0);
            throw error;
        }
        // The node reports a failed call in the body of an HTTP error, so the
        // body is read before the status is judged.
        const body = parseJson(text);
        if (body?.error)
            throw new ElementsRpcError(body.error.message ?? `Elements RPC returned HTTP ${response.status}`, response.status, body.error.code);
        if (!response.ok || body === undefined)
            throw new ElementsRpcError(response.ok
                ? "Elements RPC returned a response that is not JSON"
                : `Elements RPC returned HTTP ${response.status}`, response.status);
        return body.result;
    }
    async getUnspentOutput(txid, vout) {
        assertOutpoint(txid, vout);
        const utxo = await this.call("gettxout", [txid, vout, true]);
        if (!utxo)
            return null;
        return {
            confirmations: utxo.confirmations,
            scriptPubKey: utxo.scriptPubKey.hex,
            ...(utxo.asset === undefined ? {} : { asset: utxo.asset }),
            ...(utxo.value === undefined
                ? {}
                : { amountSats: Math.round(utxo.value * 100_000_000) }),
        };
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
export class EsploraClient {
    #url;
    #fetch;
    #timeoutMs;
    constructor(url, options = {}) {
        const { fetch: fetcher = globalThis.fetch, timeoutMs = 15_000 } = typeof options === "function" ? { fetch: options } : options;
        assertSecureUrl(url, "Esplora URL");
        if (!(timeoutMs > 0))
            throw new Error("timeoutMs must be positive milliseconds");
        this.#url = url.replace(/\/$/, "");
        this.#fetch = fetcher.bind(globalThis);
        this.#timeoutMs = timeoutMs;
    }
    /**
     * Confirmed, explicit outputs, as Elements RPC lists them: an unconfirmed
     * one cannot pay a request yet, and a confidential one has no amount to report.
     */
    async getScriptUtxos(scriptPubKey) {
        assertHex(scriptPubKey, "scriptPubKey");
        const scriptHash = bytesToHex(sha256(hexToBytes(scriptPubKey)));
        const utxos = await this.#json(`/scripthash/${scriptHash}/utxo`);
        if (!Array.isArray(utxos))
            throw new EsploraError("Esplora returned an invalid UTXO list", 200);
        return utxos.flatMap((utxo) => Number.isSafeInteger(utxo.value) &&
            utxo.status?.confirmed === true &&
            Number.isSafeInteger(utxo.status.block_height)
            ? [
                {
                    txid: utxo.txid,
                    vout: utxo.vout,
                    scriptPubKey: scriptPubKey.toLowerCase(),
                    amountSats: utxo.value,
                    ...(utxo.asset === undefined ? {} : { asset: utxo.asset }),
                    height: utxo.status.block_height,
                },
            ]
            : []);
    }
    async getUnspentOutput(txid, vout) {
        assertOutpoint(txid, vout);
        const [transaction, outspend] = await Promise.all([
            this.#json(`/tx/${txid}`, true),
            this.#json(`/tx/${txid}/outspend/${vout}`, true),
        ]);
        const output = transaction?.vout?.[vout];
        // Anything but a plain "not spent" reads as spent.
        if (!transaction || !output || outspend?.spent !== false)
            return null;
        if (typeof output.scriptpubkey !== "string")
            throw new EsploraError("Esplora returned an invalid output", 200);
        return {
            confirmations: await this.#confirmations(transaction.status),
            scriptPubKey: output.scriptpubkey,
            ...(output.asset === undefined ? {} : { asset: output.asset }),
            ...(output.value === undefined ? {} : { amountSats: output.value }),
        };
    }
    async getTransactionConfirmations(txid) {
        if (!HEX_32.test(txid)) {
            throw new Error("txid must be 32-byte hex");
        }
        const status = await this.#json(`/tx/${txid}/status`, true);
        return status ? this.#confirmations(status) : 0;
    }
    async #confirmations(status) {
        if (!status?.confirmed)
            return 0;
        const tip = await this.#json("/blocks/tip/height");
        if (!Number.isSafeInteger(tip) ||
            !Number.isSafeInteger(status.block_height))
            throw new EsploraError("Esplora returned an invalid block height", 200);
        // A tip read from a backend lagging behind the transaction counts as none.
        return Math.max(0, tip - status.block_height + 1);
    }
    async #json(path, optional = false) {
        let response;
        let text;
        try {
            ({ response, text } = await fetchText(this.#fetch, `${this.#url}${path}`, { redirect: "error" }, this.#timeoutMs));
        }
        catch (error) {
            if (error instanceof RequestTimeout)
                throw new EsploraError(`Esplora did not answer within ${this.#timeoutMs} ms`, 0);
            throw error;
        }
        if (optional && response.status === 404)
            return null;
        if (!response.ok)
            throw new EsploraError(`Esplora returned HTTP ${response.status}${text ? `: ${text.slice(0, 200)}` : ""}`, response.status);
        const body = parseJson(text);
        if (body === undefined)
            throw new EsploraError("Esplora returned a response that is not JSON", response.status);
        return body;
    }
}
export class PriceOracleClient {
    #urls;
    #fetch;
    #retries;
    #retryDelayMs;
    #timeoutMs;
    /** The node that answered last; the next call starts from it. */
    #active = 0;
    /**
     * `nodeUrls` is the coordinator, or several members of the network: only
     * the coordinator serves requests and prices, and the role moves, so the
     * client asks the others when one answers that it is not the coordinator.
     */
    constructor(nodeUrls, options = {}) {
        const { fetch: fetcher = globalThis.fetch, retries = 2, retryDelayMs = 500, timeoutMs = 15_000, } = typeof options === "function" ? { fetch: options } : options;
        const urls = typeof nodeUrls === "string" ? [nodeUrls] : [...nodeUrls];
        if (urls.length === 0)
            throw new Error("at least one coordinator URL is required");
        for (const url of urls)
            assertSecureUrl(url, "coordinator URL");
        if (!Number.isInteger(retries) || retries < 0 || !(retryDelayMs >= 0))
            throw new Error("retries must be a non-negative integer and their delay non-negative milliseconds");
        if (!(timeoutMs > 0))
            throw new Error("timeoutMs must be positive milliseconds");
        this.#urls = urls.map((url) => url.replace(/\/$/, ""));
        this.#fetch = fetcher.bind(globalThis);
        this.#retries = retries;
        this.#retryDelayMs = retryDelayMs;
        this.#timeoutMs = timeoutMs;
    }
    /** The node the next call goes to first. */
    get nodeUrl() {
        return this.#urls[this.#active];
    }
    /**
     * Read the active network assets and Storm Tree root. They are the
     * coordinator's own claims: pin the values held from an independent source
     * to have the response checked against them.
     */
    async getNetwork(verification = {}) {
        const trusted = {
            storm_eye_asset_id: verification.stormEyeAssetId,
            storm_tree_root: verification.stormTreeRoot,
            tick_asset_id: verification.tickAssetId,
            oracle_verifier_asset_id: verification.verifierAssetId,
        };
        if ((verification.network !== undefined &&
            !NETWORKS.includes(verification.network)) ||
            Object.values(trusted).some((value) => value !== undefined &&
                (typeof value !== "string" || !HEX_32.test(value))))
            throw new Error("trusted network values must be a supported network and 32-byte hex");
        const info = await this.#json("/users/network");
        if (!NETWORKS.includes(info?.network))
            throw new Error("coordinator network is not supported");
        if (verification.network !== undefined &&
            info.network !== verification.network)
            throw new Error("coordinator network does not match the trusted value");
        for (const [field, value] of Object.entries(trusted)) {
            const received = info[field];
            if (typeof received !== "string" || !HEX_32.test(received))
                throw new Error(`coordinator network ${field} must be 32-byte hex`);
            if (value !== undefined && received.toLowerCase() !== value.toLowerCase())
                throw new Error(`coordinator network ${field} does not match the trusted value`);
        }
        return {
            network: info.network,
            storm_eye_asset_id: info.storm_eye_asset_id.toLowerCase(),
            storm_tree_root: info.storm_tree_root.toLowerCase(),
            tick_asset_id: info.tick_asset_id.toLowerCase(),
            oracle_verifier_asset_id: info.oracle_verifier_asset_id.toLowerCase(),
        };
    }
    async getAccount(publicKey, verification) {
        assertXOnlyPublicKey(publicKey);
        const expected = deriveAccount(verification);
        if (publicKey.toLowerCase() !== verification.ownerPublicKey.toLowerCase())
            throw new Error("Account verification owner does not match the requested public key");
        const authScriptPubKey = verification.authScriptPubKey;
        const account = await this.#json(`/users/account/${publicKey.toLowerCase()}${authScriptPubKey === undefined ? "" : `?auth_script_pubkey=${encodeURIComponent(authScriptPubKey)}`}`);
        for (const [field, value] of Object.entries(expected)) {
            const received = account?.[field];
            if (typeof received !== "string" ||
                (field === "address" || field === "network"
                    ? received
                    : received.toLowerCase()) !== value)
                throw new Error(`coordinator Account ${field} does not match the trusted derivation`);
        }
        return expected;
    }
    async submitTickRequest(request) {
        return this.#json("/users/requests", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(request),
        }, false);
    }
    getTickRequest(requestHash) {
        return this.#tickRequest(requestHash);
    }
    #tickRequest(requestHash, signal) {
        if (!HEX_32.test(requestHash)) {
            throw new Error("request hash must be 32-byte hex");
        }
        return this.#json(`/users/requests/${requestHash}`, undefined, true, signal);
    }
    /**
     * Poll a request until it is `executed`. A `failed` request rejects with the
     * coordinator's reason, as does a timeout or an aborted `signal`.
     */
    async waitForTickRequest(requestHash, options = {}) {
        const { timeoutMs = 900_000, intervalMs = 5_000, signal } = options;
        if (!(timeoutMs > 0) || !(intervalMs > 0))
            throw new Error("timeout and interval must be positive milliseconds");
        signal?.throwIfAborted();
        // Ends a status read or a pause that the caller aborts or that would
        // outlast the wait, so a node that stops answering cannot hold it.
        const stop = new AbortController();
        const expired = new Error("the wait expired");
        const timer = setTimeout(() => stop.abort(expired), timeoutMs);
        const forward = () => stop.abort(signal?.reason);
        signal?.addEventListener("abort", forward, { once: true });
        const deadline = Date.now() + timeoutMs;
        let status;
        try {
            for (;;) {
                status = await this.#tickRequest(requestHash, stop.signal);
                options.onStatus?.(status);
                if (status.status === "executed")
                    return status;
                if (status.status === "failed")
                    throw new Error(`user request failed: ${status.payload ?? "no reason given"}`);
                if (Date.now() + intervalMs > deadline)
                    throw stillWaiting(status, timeoutMs);
                await sleep(intervalMs, stop.signal);
            }
        }
        catch (error) {
            if (error === expired)
                throw stillWaiting(status, timeoutMs);
            throw error;
        }
        finally {
            clearTimeout(timer);
            signal?.removeEventListener("abort", forward);
        }
    }
    getPriceFeeds() {
        return this.#json("/price-feeds");
    }
    getPriceFeed(feedId) {
        assertFeedId(feedId);
        return this.#json(`/price-feeds/${feedId}`);
    }
    /**
     * `repeatable` is false for a submission: a node that did not answer may
     * still have queued it, so it is neither retried nor sent to another node.
     */
    async #json(path, init, repeatable = true, signal) {
        for (let attempt = 0;; attempt++) {
            let failure;
            // One pass over the nodes, from the one that answered last.
            for (let offset = 0; offset < this.#urls.length; offset++) {
                const index = (this.#active + offset) % this.#urls.length;
                try {
                    const result = await this.#request(index, path, init, signal);
                    this.#active = index;
                    return result;
                }
                catch (error) {
                    if (!(error instanceof OracleApiError))
                        throw error;
                    // "Not the coordinator" says the least about why the call failed.
                    if (failure === undefined || failure.code === "not_coordinator")
                        failure = error;
                    const elsewhere = error.code === "not_coordinator" ||
                        (repeatable && isTransient(error));
                    if (!elsewhere)
                        break;
                }
            }
            const error = failure;
            if (!repeatable || !isTransient(error) || attempt >= this.#retries)
                throw error;
            await sleep(this.#retryDelayMs * 2 ** attempt, signal);
        }
    }
    async #request(node, path, init, signal) {
        let response;
        let text;
        try {
            ({ response, text } = await fetchText(this.#fetch, `${this.#urls[node]}${path}`, { ...init, redirect: "error" }, this.#timeoutMs, signal));
        }
        catch (error) {
            if (signal?.aborted)
                throw signal.reason;
            const late = error instanceof RequestTimeout;
            throw new OracleApiError(late
                ? `node did not answer within ${this.#timeoutMs} ms`
                : error instanceof Error
                    ? error.message
                    : String(error), late ? "timeout" : "network", 0, { cause: error });
        }
        const body = parseJson(text);
        if (!response.ok) {
            const reported = body?.error;
            const message = typeof reported === "string" ? reported : `HTTP ${response.status}`;
            throw new OracleApiError(message, oracleErrorCode(response.status, message), response.status);
        }
        if (body === undefined)
            throw new OracleApiError("coordinator returned a response that is not JSON", "invalid_response", response.status);
        return body;
    }
}
/** Derive an Account and Tick from independently trusted contract leaves and asset IDs. */
export function deriveAccount(verification) {
    if (!verification || typeof verification !== "object")
        throw new Error("trusted Account verification context is required");
    assertXOnlyPublicKey(verification.ownerPublicKey);
    if (!NETWORKS.includes(verification.network))
        throw new Error("unsupported trusted Account network");
    if ([
        verification.stormEyeAssetId,
        verification.tickAssetId,
        verification.verifierAssetId,
        verification.accountTapleafHash,
        verification.tickTapleafHash,
    ].some((value) => typeof value !== "string" || !HEX_32.test(value)))
        throw new Error("trusted Account assets and tapleaf hashes must be 32-byte hex");
    if (verification.authScriptPubKey !== undefined)
        validateAuthMethod({
            kind: "scriptPubKey-auth",
            auth_data: verification.authScriptPubKey,
        });
    const scriptPubKey = elementsTaprootScript(UNSPENDABLE_INTERNAL_KEY, verification.accountTapleafHash);
    const tickScriptPubKey = elementsTaprootScript(UNSPENDABLE_INTERNAL_KEY, verification.tickTapleafHash);
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
export function createWalletTickRequest(compressedPublicKey, feeUtxos, authScriptPubKey) {
    if (!/^(02|03)[0-9a-f]{64}$/i.test(compressedPublicKey))
        throw new Error("wallet public key must be compressed secp256k1 hex");
    secp256k1.ProjectivePoint.fromHex(compressedPublicKey);
    if (feeUtxos.length === 0 ||
        feeUtxos.some((outpoint) => !OUTPOINT.test(outpoint)))
        throw new Error("fee UTXOs must contain txid:vout outpoints");
    const authMethod = {
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
export function walletRequestSigningMessage(request) {
    if (request.header.signature_scheme !== WALLET_REQUEST_SIGNATURE_SCHEME ||
        !request.header.signing_public_key) {
        throw new Error("request must use wallet message authorization");
    }
    return `${REQUEST_TAG}\n${WALLET_REQUEST_SIGNATURE_SCHEME}\n${JSON.stringify([
        request.header.public_key,
        request.header.signing_public_key,
        request.header.fee_utxos,
        request.requests,
    ])}`;
}
function assertFeedId(feedId) {
    if (!Number.isInteger(feedId) || feedId < 0 || feedId > 0xffffffff) {
        throw new Error("price feed id must be an unsigned 32-bit integer");
    }
}
export function createWalletSignedPriceRequest(compressedPublicKey, feeUtxos, authScriptPubKey, priceFeedId, options = {}) {
    assertFeedId(priceFeedId);
    const request = createWalletTickRequest(compressedPublicKey, feeUtxos, authScriptPubKey);
    const tick = request.requests[0];
    if (!tick)
        throw new Error("wallet request has no Tick template");
    request.requests = [
        {
            kind: "signed-price-data",
            payload: JSON.stringify({
                ...JSON.parse(tick.payload),
                price_feed_id: priceFeedId,
            }),
        },
    ];
    if (options.withTick)
        request.requests.push(tick);
    return request;
}
export function createTickRequest(privateKey, feeUtxos, authMethod) {
    return buildRequest(privateKey, feeUtxos, "tick-utxo", authMethod);
}
/**
 * A priced request: issues an Oracle Verifier and returns the signed rate,
 * checked by {@link verifySignedPriceData}. `withTick` orders a Tick in the
 * same batch, at the fees of a second output.
 */
export function createSignedPriceRequest(privateKey, feeUtxos, priceFeedId, authMethod, options = {}) {
    if (!Number.isInteger(priceFeedId) ||
        priceFeedId < 0 ||
        priceFeedId > 0xffffffff) {
        throw new Error("price feed id must be an unsigned 32-bit integer");
    }
    return buildRequest(privateKey, feeUtxos, "signed-price-data", authMethod, priceFeedId, options.withTick);
}
function buildRequest(privateKey, feeUtxos, kind, authMethod, priceFeedId, withTick) {
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
    // The network rejects a payload carrying any field it does not know, and a
    // plain Tick must name no feed at all, so the key is present only for a
    // priced request and spelled as the specification spells it.
    const payload = JSON.stringify(priceFeedId === undefined
        ? { utxo_auth_method: selectedAuth }
        : { utxo_auth_method: selectedAuth, price_feed_id: priceFeedId });
    const request = {
        header: {
            signature: "",
            public_key: publicKey,
            fee_utxos: [...feeUtxos],
        },
        requests: [{ kind, payload }],
    };
    // A contract holds a price against the time of a Tick spent beside its
    // Verifier, so one batch can order both under the same authentication.
    if (withTick)
        request.requests.push({
            kind: "tick-utxo",
            payload: JSON.stringify({ utxo_auth_method: selectedAuth }),
        });
    request.header.signature = bytesToHex(schnorr.sign(tickRequestSigningHash(request), privateKey));
    return request;
}
export function tickRequestSigningHash(request) {
    const message = request.requests.map(({ payload }) => payload).join("") +
        request.header.fee_utxos.join("");
    const tagHash = sha256(utf8ToBytes(REQUEST_TAG));
    return sha256(new Uint8Array([...tagHash, ...tagHash, ...utf8ToBytes(message)]));
}
/** The 32 canonical bytes the network signs, as the numbers they encode. */
export function decodePriceData(priceData) {
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
export function verifySignedPriceData(details, verification) {
    try {
        if (typeof verification.now !== "bigint" || verification.now < 0n)
            return false;
        const price = authenticatedPrice(details, verification);
        return (price !== null &&
            price.receivedAt <= verification.now &&
            verification.now < price.validUntil);
    }
    catch {
        return false;
    }
}
/**
 * The rate, when a member of the trusted Storm Tree signed it for the expected
 * feed and decimals; null otherwise. The time it is read at is the caller's.
 */
function authenticatedPrice(details, verification) {
    try {
        if (!HEX_32.test(verification.stormTreeRoot))
            return null;
        assertFeedId(verification.feedId);
        assertFeedId(verification.decimals);
        const price = decodePriceData(details.price_data);
        if (price.feedId !== verification.feedId ||
            price.decimals !== verification.decimals ||
            price.validUntil <= price.receivedAt ||
            price.validUntil - price.receivedAt > PRICE_VALIDITY_SECONDS)
            return null;
        const { signature, branch, proof } = details.storm_tree_bloom;
        if (!HEX_32.test(branch) ||
            !/^[0-9a-f]{128}$/i.test(signature) ||
            !Array.isArray(proof) ||
            proof.length < 1 ||
            proof.length > MAX_STORM_TREE_DEPTH)
            return null;
        let root = sha256(new Uint8Array([...hexToBytes(branch), 0x01]));
        for (const sibling of proof) {
            if (typeof sibling.right !== "boolean" || !HEX_32.test(sibling.hash))
                return null;
            const hash = hexToBytes(sibling.hash);
            root = sha256(new Uint8Array(sibling.right ? [...hash, ...root] : [...root, ...hash]));
        }
        if (bytesToHex(root) !== verification.stormTreeRoot.toLowerCase())
            return null;
        const tagHash = sha256(utf8ToBytes(PRICE_TAG));
        const message = sha256(new Uint8Array([
            ...tagHash,
            ...tagHash,
            ...hexToBytes(details.price_data),
        ]));
        return schnorr.verify(hexToBytes(signature), message, hexToBytes(branch))
            ? price
            : null;
    }
    catch {
        return null;
    }
}
export function parseExecutedTick(status) {
    if (status.payload === null ||
        (status.status !== "processing" &&
            status.status !== "included" &&
            status.status !== "executed")) {
        return null;
    }
    return JSON.parse(status.payload);
}
/** The one result of `kind` in a finalized batch, or null before it is final. */
function executedResult(status, kind, name) {
    if (status.status !== "executed")
        return null;
    const executed = parseExecutedTick(status);
    if (!executed)
        return null;
    if (!HEX_32.test(executed.txid) || !Array.isArray(executed.results))
        throw new Error("invalid issuance result");
    const results = executed.results.filter((result) => result.kind === kind);
    if (results.length !== 1)
        throw new Error(`expected exactly one issued ${name}`);
    const result = results[0];
    if (!result)
        throw new Error(`issuance result has no ${name}`);
    if (!Number.isInteger(result.vout) ||
        result.vout < 0 ||
        result.vout > 0xffffffff)
        throw new Error(`invalid ${name} output index`);
    return { txid: executed.txid, result };
}
/** Authenticate an executed response; its returned outpoint is not chain-verified. */
export function parseExecutedSignedPrice(status, verification) {
    const executed = executedResult(status, "signed-price-data", "Verifier");
    if (!executed)
        return null;
    const signedPrice = JSON.parse(executed.result.payload);
    decodePriceData(signedPrice.price_data);
    if (!verifySignedPriceData(signedPrice, verification))
        throw new Error("oracle price does not verify against the trusted context");
    return {
        txid: executed.txid,
        verifierVout: executed.result.vout,
        signedPrice,
    };
}
/** Check a finalized price and its confirmed, unspent Verifier via an independent chain source. */
export async function verifyExecutedSignedPrice(status, verification, chain) {
    assertVerifierContext(verification);
    const executed = parseExecutedSignedPrice(status, verification);
    if (!executed)
        return null;
    await assertIssuedVerifier(executed, verification, chain);
    return executed;
}
function assertTickContext(verification) {
    if (!HEX_32.test(verification.tickAssetId) ||
        !HEX_32.test(verification.tickTapleafHash))
        throw new Error("trusted Tick asset and tapleaf hash must be 32-byte hex");
}
function assertVerifierContext(verification) {
    if (!HEX_32.test(verification.verifierAssetId) ||
        !HEX_32.test(verification.verifierTapleafHash))
        throw new Error("trusted Verifier asset and tapleaf hash must be 32-byte hex");
}
/** One unit of the Verifier asset, confirmed, unspent and locked to the signing branch. */
async function assertIssuedVerifier(executed, verification, chain) {
    const scriptPubKey = elementsTaprootScript(executed.signedPrice.storm_tree_bloom.branch, verification.verifierTapleafHash);
    const utxo = await chain.getUnspentOutput(executed.txid, executed.verifierVout);
    if (!utxo ||
        !Number.isSafeInteger(utxo.confirmations) ||
        utxo.confirmations < 1 ||
        utxo.asset?.toLowerCase() !== verification.verifierAssetId.toLowerCase() ||
        utxo.amountSats !== 1 ||
        utxo.scriptPubKey.toLowerCase() !== scriptPubKey)
        throw new Error("confirmed unspent Verifier does not match the trusted context");
}
/**
 * Check a finalized Tick via an independent chain source: confirmed, unspent,
 * in the Tick asset, locked by the trusted voucher leaf, and carrying the
 * reported time.
 */
export async function verifyExecutedTick(status, verification, chain) {
    assertTickContext(verification);
    const executed = executedResult(status, "tick-utxo", "Tick");
    if (!executed)
        return null;
    const { timestamp } = JSON.parse(executed.result.payload);
    if (!Number.isSafeInteger(timestamp) || timestamp <= 0)
        throw new Error("invalid Tick timestamp");
    const scriptPubKey = elementsTaprootScript(UNSPENDABLE_INTERNAL_KEY, verification.tickTapleafHash);
    const utxo = await chain.getUnspentOutput(executed.txid, executed.result.vout);
    if (!utxo ||
        !Number.isSafeInteger(utxo.confirmations) ||
        utxo.confirmations < 1 ||
        utxo.asset?.toLowerCase() !== verification.tickAssetId.toLowerCase() ||
        utxo.amountSats !== timestamp ||
        utxo.scriptPubKey.toLowerCase() !== scriptPubKey)
        throw new Error("confirmed unspent Tick does not match the trusted context");
    return {
        txid: executed.txid,
        vout: executed.result.vout,
        asset: verification.tickAssetId.toLowerCase(),
        timestamp,
        scriptPubKey,
    };
}
/**
 * Check the Tick and the Verifier one batch issued, as a contract spending
 * them together does: each is the confirmed, unspent output its covenant
 * expects, a current member signed the rate, and the rate is still valid at
 * the time the Tick carries. No clock is read: the pair is held against the
 * Tick's time alone, which is what `verify_tick_with_price` enforces.
 */
export async function verifyExecutedTickWithPrice(status, verification, chain) {
    assertVerifierContext(verification);
    assertTickContext(verification);
    const executed = executedResult(status, "signed-price-data", "Verifier");
    if (!executed)
        return null;
    // The signature is checked before the chain is asked about either output.
    const signedPrice = JSON.parse(executed.result.payload);
    const price = authenticatedPrice(signedPrice, verification);
    if (!price)
        throw new Error("oracle price does not verify against the trusted context");
    const tick = await verifyExecutedTick(status, verification, chain);
    if (!tick)
        return null;
    if (BigInt(tick.timestamp) >= price.validUntil)
        throw new Error("oracle price is not valid at the time of its Tick");
    const verifier = {
        txid: executed.txid,
        verifierVout: executed.result.vout,
        signedPrice,
    };
    await assertIssuedVerifier(verifier, verification, chain);
    return { ...verifier, tick, price };
}
function elementsTaprootScript(internalPublicKey, tapleafHash) {
    const tagHash = sha256(utf8ToBytes("TapTweak/elements"));
    const tweakHash = sha256(new Uint8Array([
        ...tagHash,
        ...tagHash,
        ...hexToBytes(internalPublicKey),
        ...hexToBytes(tapleafHash),
    ]));
    const tweak = BigInt(`0x${bytesToHex(tweakHash)}`);
    if (tweak >= secp256k1.CURVE.n)
        throw new Error("invalid Elements Taproot tweak");
    const internalKey = secp256k1.ProjectivePoint.fromHex(`02${internalPublicKey}`);
    const outputKey = tweak === 0n
        ? internalKey
        : internalKey.add(secp256k1.ProjectivePoint.BASE.multiply(tweak));
    return `5120${bytesToHex(outputKey.toRawBytes(true).slice(1))}`;
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
/** Why a wait ended before the request was final. */
function stillWaiting(status, timeoutMs) {
    return new Error(status === undefined
        ? `user request status was not read within ${timeoutMs} ms`
        : `user request is still ${status.status} after ${timeoutMs} ms`);
}
/** A failure that asking again, or asking another node, may get past. */
function isTransient(error) {
    return [
        "network",
        "timeout",
        "rate_limited",
        "unavailable",
        "server_error",
    ].includes(error.code);
}
/** No answer, or no whole body, within the time a request is given. */
class RequestTimeout extends Error {
}
/**
 * `fetch` and the body of its answer, given up once `timeoutMs` pass or
 * `signal` aborts, whether or not the fetch implementation heeds its signal.
 */
async function fetchText(fetcher, url, init, timeoutMs, signal) {
    signal?.throwIfAborted();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new RequestTimeout(`no answer within ${timeoutMs} ms`)), timeoutMs);
    const forward = () => controller.abort(signal?.reason);
    signal?.addEventListener("abort", forward, { once: true });
    const stopped = new Promise((_, reject) => controller.signal.addEventListener("abort", () => reject(controller.signal.reason), { once: true }));
    try {
        const response = await Promise.race([
            fetcher(url, { ...init, signal: controller.signal }),
            stopped,
        ]);
        const text = await Promise.race([response.text(), stopped]);
        return { response, text };
    }
    finally {
        clearTimeout(timer);
        signal?.removeEventListener("abort", forward);
    }
}
function sleep(milliseconds, signal) {
    return new Promise((resolve, reject) => {
        if (signal?.aborted)
            return reject(signal.reason);
        const abort = () => {
            clearTimeout(timer);
            reject(signal?.reason);
        };
        const timer = setTimeout(() => {
            signal?.removeEventListener("abort", abort);
            resolve();
        }, milliseconds);
        signal?.addEventListener("abort", abort, { once: true });
    });
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
function assertOutpoint(txid, vout) {
    if (!HEX_32.test(txid) ||
        !Number.isInteger(vout) ||
        vout < 0 ||
        vout > 0xffffffff)
        throw new Error("outpoint must be a 32-byte hex txid and an output index");
}
function assertSecureUrl(value, name) {
    const url = new URL(value);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
        throw new Error(`${name} must use HTTPS (HTTP is loopback-only)`);
}
function oracleErrorCode(status, message) {
    if (status === 503)
        return message === NOT_COORDINATOR ? "not_coordinator" : "unavailable";
    if (status >= 500)
        return "server_error";
    if (status === 401 || status === 403)
        return "unauthorized";
    if (status === 404)
        return "not_found";
    if (status === 408)
        return "timeout";
    if (status === 409)
        return "conflict";
    if (status === 429)
        return "rate_limited";
    return "invalid_request";
}
/** The parsed body, or undefined when it is not JSON. */
function parseJson(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        return undefined;
    }
}
function assertHex(value, name) {
    if (value.length === 0 ||
        value.length % 2 !== 0 ||
        !/^[0-9a-f]+$/i.test(value)) {
        throw new Error(`${name} must be hex`);
    }
}

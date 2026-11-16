export declare const WALLET_REQUEST_SIGNATURE_SCHEME = "bitcoin-signed-message-ecdsa-v1";
/** `fetch`, as far as the SDK calls it. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;
export type OracleErrorCode = "invalid_request" | "unauthorized" | "not_found" | "conflict"
/** A 408, or no answer within the client's `timeoutMs` (status 0). */
 | "timeout" | "rate_limited"
/** The node answered, but only the coordinator serves this route. */
 | "not_coordinator" | "unavailable" | "server_error"
/** A success whose body is not JSON. */
 | "invalid_response"
/** No node answered. */
 | "network";
/** A node answer that is not a success, or no answer at all. */
export declare class OracleApiError extends Error {
    readonly code: OracleErrorCode;
    /** The HTTP status; 0 when the node did not answer. */
    readonly status: number;
    constructor(message: string, code: OracleErrorCode, status: number, options?: ErrorOptions);
}
/** An Elements RPC failure, with the node's own message when it sent one. */
export declare class ElementsRpcError extends Error {
    readonly status: number;
    /** The JSON-RPC error code, such as -5 for an unknown transaction. */
    readonly code: number | undefined;
    constructor(message: string, status: number, code?: number);
}
/** An Esplora answer that is not a success. */
export declare class EsploraError extends Error {
    readonly status: number;
    constructor(message: string, status: number);
}
export type OracleNetwork = "liquidv1" | "liquidtestnet" | "elementsregtest";
/** The active network assets and Storm Tree root, as the coordinator reports them. */
export type OracleNetworkInfo = {
    network: OracleNetwork;
    storm_eye_asset_id: string;
    storm_tree_root: string;
    tick_asset_id: string;
    oracle_verifier_asset_id: string;
};
/** Independently pinned network values; each one supplied must match the response. */
export type NetworkVerification = {
    network?: OracleNetwork;
    stormEyeAssetId?: string;
    tickAssetId?: string;
    verifierAssetId?: string;
    stormTreeRoot?: string;
};
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
export type TickAuthMethod = {
    kind: "signature-auth";
    auth_data: string;
} | {
    kind: "asset-id-auth";
    auth_data: string;
} | {
    kind: "scriptPubKey-auth";
    auth_data: string;
};
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
    requests: Array<{
        kind: TickRequestKind;
        payload: string;
    }>;
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
export type WaitOptions = {
    /** Give up after this long; 15 minutes by default. */
    timeoutMs?: number;
    /** Pause between status reads; 5 seconds by default. */
    intervalMs?: number;
    signal?: AbortSignal;
    /** Called with every status read, the final one included. */
    onStatus?: (status: TickRequestStatus) => void;
};
export type StormTreeBloom = {
    signature: string;
    branch: string;
    proof: Array<{
        right: boolean;
        hash: string;
    }>;
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
export type IssuedTickVerification = {
    /** Tick asset ID from independently verified network issuance. */
    tickAssetId: string;
    /** Locally compiled voucher leaf for the requested authentication method. */
    tickTapleafHash: string;
};
/** No clock: the pair is held against the Tick's own time, as a contract holds it. */
export type IssuedTickWithPriceVerification = Omit<IssuedPriceVerification, "now"> & IssuedTickVerification;
export type IssuedTickWithPrice = {
    txid: string;
    tick: IssuedTick;
    verifierVout: number;
    signedPrice: SignedPriceData;
    /** The signed rate, decoded. */
    price: PriceFeedData;
};
/** An output as the chain checks read it; a confidential one has no asset or amount. */
export type ChainOutput = {
    confirmations: number;
    scriptPubKey: string;
    asset?: string;
    amountSats?: number;
};
/** Read access to the chain, through Elements RPC or Esplora. */
export interface ChainClient {
    /** The script's confirmed, explicit outputs: those a request can be paid from. */
    getScriptUtxos(scriptPubKey: string): Promise<OracleUtxo[]>;
    /** The output while it is unspent, mempool spends included; null otherwise. */
    getUnspentOutput(txid: string, vout: number): Promise<ChainOutput | null>;
}
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
    fetch?: FetchLike;
    /** How long the node is given to answer; 15 seconds by default. */
    timeoutMs?: number;
};
export declare class ElementsRpcClient implements ChainClient {
    #private;
    constructor(options: RpcOptions);
    call<Result>(method: string, params?: unknown[]): Promise<Result>;
    getUnspentOutput(txid: string, vout: number): Promise<ChainOutput | null>;
    getScriptUtxos(scriptPubKey: string): Promise<OracleUtxo[]>;
    getTransactionConfirmations(txid: string): Promise<number>;
    broadcast(transactionHex: string, maxBurnSats?: number): Promise<string>;
}
/**
 * Chain reads through an Esplora HTTP API, which public Liquid explorers
 * serve to browsers. It does not broadcast: a Tick redemption burns, and only
 * a node asked directly lifts its burn limit for one transaction.
 */
export type EsploraClientOptions = {
    fetch?: FetchLike;
    /** How long Esplora is given to answer; 15 seconds by default. */
    timeoutMs?: number;
};
export declare class EsploraClient implements ChainClient {
    #private;
    constructor(url: string, options?: FetchLike | EsploraClientOptions);
    /**
     * Confirmed, explicit outputs, as Elements RPC lists them: an unconfirmed
     * one cannot pay a request yet, and a confidential one has no amount to report.
     */
    getScriptUtxos(scriptPubKey: string): Promise<OracleUtxo[]>;
    getUnspentOutput(txid: string, vout: number): Promise<ChainOutput | null>;
    getTransactionConfirmations(txid: string): Promise<number>;
}
export type OracleClientOptions = {
    fetch?: FetchLike;
    /**
     * Extra attempts for a read no node answered in time, or answered with 408,
     * 429 or a server error; 2 by default. A submission is never repeated.
     */
    retries?: number;
    /** Pause before the first retry, doubled for each later one; 500 ms by default. */
    retryDelayMs?: number;
    /** How long one node is given to answer; 15 seconds by default. */
    timeoutMs?: number;
};
export declare class PriceOracleClient {
    #private;
    /**
     * `nodeUrls` is the coordinator, or several members of the network: only
     * the coordinator serves requests and prices, and the role moves, so the
     * client asks the others when one answers that it is not the coordinator.
     */
    constructor(nodeUrls: string | readonly string[], options?: FetchLike | OracleClientOptions);
    /** The node the next call goes to first. */
    get nodeUrl(): string;
    /**
     * Read the active network assets and Storm Tree root. They are the
     * coordinator's own claims: pin the values held from an independent source
     * to have the response checked against them.
     */
    getNetwork(verification?: NetworkVerification): Promise<OracleNetworkInfo>;
    getAccount(publicKey: string, verification: AccountVerification): Promise<OracleAccount>;
    submitTickRequest(request: TickRequest): Promise<{
        request_hash: string;
    }>;
    getTickRequest(requestHash: string): Promise<TickRequestStatus>;
    /**
     * Poll a request until it is `executed`. A `failed` request rejects with the
     * coordinator's reason, as does a timeout or an aborted `signal`.
     */
    waitForTickRequest(requestHash: string, options?: WaitOptions): Promise<TickRequestStatus>;
    getPriceFeeds(): Promise<PriceFeedInfo[]>;
    getPriceFeed(feedId: number): Promise<PriceFeedRate>;
}
/** Derive an Account and Tick from independently trusted contract leaves and asset IDs. */
export declare function deriveAccount(verification: AccountVerification): OracleAccount;
export declare function publicKeyFromPrivateKey(privateKey: string): string;
export declare function signSchnorrDigest(privateKey: string, digest: string): string;
export declare function createWalletTickRequest(compressedPublicKey: string, feeUtxos: string[], authScriptPubKey: string): TickRequest;
export declare function walletRequestSigningMessage(request: TickRequest): string;
export declare function createWalletSignedPriceRequest(compressedPublicKey: string, feeUtxos: string[], authScriptPubKey: string, priceFeedId: number, options?: {
    withTick?: boolean;
}): TickRequest;
export declare function createTickRequest(privateKey: string, feeUtxos: string[], authMethod?: TickAuthMethod): TickRequest;
/**
 * A priced request: issues an Oracle Verifier and returns the signed rate,
 * checked by {@link verifySignedPriceData}. `withTick` orders a Tick in the
 * same batch, at the fees of a second output.
 */
export declare function createSignedPriceRequest(privateKey: string, feeUtxos: string[], priceFeedId: number, authMethod?: TickAuthMethod, options?: {
    withTick?: boolean;
}): TickRequest;
export declare function tickRequestSigningHash(request: TickRequest): Uint8Array;
/** The 32 canonical bytes the network signs, as the numbers they encode. */
export declare function decodePriceData(priceData: string): PriceFeedData;
/**
 * Authenticate a fresh rate against the caller's trusted current Storm Eye root.
 * This does not establish issuance, confirmation, or unspentness of a Verifier.
 */
export declare function verifySignedPriceData(details: SignedPriceData, verification: SignedPriceVerification): boolean;
export declare function parseExecutedTick(status: TickRequestStatus): {
    txid: string;
    results: TickRequestResult[];
} | null;
/** Authenticate an executed response; its returned outpoint is not chain-verified. */
export declare function parseExecutedSignedPrice(status: TickRequestStatus, verification: SignedPriceVerification): {
    txid: string;
    verifierVout: number;
    signedPrice: SignedPriceData;
} | null;
/** Check a finalized price and its confirmed, unspent Verifier via an independent chain source. */
export declare function verifyExecutedSignedPrice(status: TickRequestStatus, verification: IssuedPriceVerification, chain: ChainClient): Promise<ReturnType<typeof parseExecutedSignedPrice>>;
/**
 * Check a finalized Tick via an independent chain source: confirmed, unspent,
 * in the Tick asset, locked by the trusted voucher leaf, and carrying the
 * reported time.
 */
export declare function verifyExecutedTick(status: TickRequestStatus, verification: IssuedTickVerification, chain: ChainClient): Promise<IssuedTick | null>;
/**
 * Check the Tick and the Verifier one batch issued, as a contract spending
 * them together does: each is the confirmed, unspent output its covenant
 * expects, a current member signed the rate, and the rate is still valid at
 * the time the Tick carries. No clock is read: the pair is held against the
 * Tick's time alone, which is what `verify_tick_with_price` enforces.
 */
export declare function verifyExecutedTickWithPrice(status: TickRequestStatus, verification: IssuedTickWithPriceVerification, chain: ChainClient): Promise<IssuedTickWithPrice | null>;
export declare function createTickSpendPlan(tick: IssuedTick, resolution: PredictionResolution): TickSpendPlan;

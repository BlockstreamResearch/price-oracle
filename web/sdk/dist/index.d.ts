export declare const WALLET_REQUEST_SIGNATURE_SCHEME = "bitcoin-signed-message-ecdsa-v1";
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
export declare class ElementsRpcClient {
    #private;
    constructor(options: RpcOptions);
    call<Result>(method: string, params?: unknown[]): Promise<Result>;
    getScriptUtxos(scriptPubKey: string): Promise<OracleUtxo[]>;
    getTransactionConfirmations(txid: string): Promise<number>;
    broadcast(transactionHex: string, maxBurnSats?: number): Promise<string>;
}
export declare class PriceOracleClient {
    #private;
    constructor(coordinatorUrl: string, fetcher?: typeof fetch);
    getAccount(publicKey: string, verification: AccountVerification): Promise<OracleAccount>;
    submitTickRequest(request: TickRequest): Promise<{
        request_hash: string;
    }>;
    getTickRequest(requestHash: string): Promise<TickRequestStatus>;
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
 * checked by {@link verifySignedPriceData}.
 */
export declare function createSignedPriceRequest(privateKey: string, feeUtxos: string[], priceFeedId: number, authMethod?: TickAuthMethod): TickRequest;
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
/** Check a finalized price and its confirmed, unspent Verifier via independent RPC. */
export declare function verifyExecutedSignedPrice(status: TickRequestStatus, verification: IssuedPriceVerification, elements: ElementsRpcClient): Promise<ReturnType<typeof parseExecutedSignedPrice>>;
export declare function createTickSpendPlan(tick: IssuedTick, resolution: PredictionResolution): TickSpendPlan;

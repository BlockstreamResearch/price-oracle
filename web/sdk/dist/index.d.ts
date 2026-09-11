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
export type TickRequest = {
    header: {
        signature: string;
        public_key: string;
        fee_utxos: string[];
    };
    requests: Array<{
        kind: "tick-utxo";
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
    getAccount(publicKey: string): Promise<OracleAccount>;
    submitTickRequest(request: TickRequest): Promise<{
        request_hash: string;
    }>;
    getTickRequest(requestHash: string): Promise<TickRequestStatus>;
}
export declare function publicKeyFromPrivateKey(privateKey: string): string;
export declare function signSchnorrDigest(privateKey: string, digest: string): string;
export declare function createTickRequest(privateKey: string, feeUtxos: string[], authMethod?: TickAuthMethod): TickRequest;
export declare function tickRequestSigningHash(request: TickRequest): Uint8Array;
export declare function parseExecutedTick(status: TickRequestStatus): {
    txid: string;
    results: TickRequestResult[];
} | null;
export declare function createTickSpendPlan(tick: IssuedTick, resolution: PredictionResolution): TickSpendPlan;

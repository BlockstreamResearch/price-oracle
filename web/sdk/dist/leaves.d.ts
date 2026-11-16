import type { AccountVerification, TickAuthMethod } from "./index.js";
/**
 * Compiles the contract leaves the SDK pins. The module is the SimplicityHL
 * compiler the nodes run, built for WebAssembly together with the contract
 * sources of this SDK's revision, so it stands in for a local Rust build.
 */
export type LeafCompiler = {
    /** The Account leaf of `ownerPublicKey`. */
    accountTapleafHash(stormEyeAssetId: string, ownerPublicKey: string): string;
    /** The leaf of a Tick or Verifier issued for `authMethod`. */
    voucherTapleafHash(stormEyeAssetId: string, authMethod: TickAuthMethod): string;
    /**
     * The context `getAccount` takes, with both leaves compiled: the Tick for
     * `authScriptPubKey` when one is given, for the owner's signature otherwise.
     */
    accountVerification(context: Omit<AccountVerification, "accountTapleafHash" | "tickTapleafHash">): AccountVerification;
};
/** Where the module is read from: its bytes, a response, or its address. */
export type LeafCompilerSource = string | URL | Response | Promise<Response> | BufferSource | WebAssembly.Module;
/**
 * Load the leaf compiler. Without a `source` the module shipped beside this
 * file is fetched, or read from disk when the SDK runs from one.
 */
export declare function loadLeafCompiler(source?: LeafCompilerSource): Promise<LeafCompiler>;

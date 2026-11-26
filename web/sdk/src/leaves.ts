import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import type { AccountVerification, TickAuthMethod } from "./index.js";

const HEX_32 = /^[0-9a-f]{64}$/i;
/** WASI errno values: a bad descriptor, and a call the host does not have. */
const EBADF = 8;
const ENOSYS = 52;

/**
 * Compiles the contract leaves the SDK pins. The module is the SimplicityHL
 * compiler the nodes run, built for WebAssembly together with the contract
 * sources of this SDK's revision, so it stands in for a local Rust build.
 */
export type LeafCompiler = {
  /** The Account leaf of `ownerPublicKey`. */
  accountTapleafHash(stormEyeAssetId: string, ownerPublicKey: string): string;
  /** The leaf of a Tick or Verifier issued for `authMethod`. */
  voucherTapleafHash(
    stormEyeAssetId: string,
    authMethod: TickAuthMethod,
  ): string;
  /**
   * The context `getAccount` takes, with both leaves compiled: the Tick for
   * `authScriptPubKey` when one is given, for the owner's signature otherwise.
   */
  accountVerification(
    context: Omit<
      AccountVerification,
      "accountTapleafHash" | "tickTapleafHash"
    >,
  ): AccountVerification;
};

/** Where the module is read from: its bytes, a response, or its address. */
export type LeafCompilerSource =
  | string
  | URL
  | Response
  | Promise<Response>
  | BufferSource
  | WebAssembly.Module;

/**
 * Load the leaf compiler. Without a `source` the module shipped beside this
 * file is fetched, or read from disk when the SDK runs from one.
 */
export async function loadLeafCompiler(
  source: LeafCompilerSource = new URL("./leaves.wasm", import.meta.url),
): Promise<LeafCompiler> {
  const module = await compile(source);
  let memory: WebAssembly.Memory | undefined;
  // What the module printed last: a panic explains itself there.
  let printed = "";
  const view = () => new DataView((memory as WebAssembly.Memory).buffer);
  const zeroSizes = (count: number, size: number) => {
    view().setUint32(count, 0, true);
    view().setUint32(size, 0, true);
    return 0;
  };
  // The compiler reads no files, arguments or environment; the standard
  // library still asks for the clock and for random hash seeds.
  const wasi: Record<string, (...args: never[]) => number> = {
    random_get: (pointer: number, length: number) => {
      const bytes = new Uint8Array(
        (memory as WebAssembly.Memory).buffer,
        pointer,
        length,
      );
      for (let offset = 0; offset < length; offset += 65_536)
        crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
      return 0;
    },
    clock_time_get: (_id: number, _precision: bigint, pointer: number) => {
      view().setBigUint64(pointer, BigInt(Date.now()) * 1_000_000n, true);
      return 0;
    },
    fd_write: (
      _descriptor: number,
      vectors: number,
      count: number,
      written: number,
    ) => {
      let total = 0;
      for (let index = 0; index < count; index++) {
        const pointer = view().getUint32(vectors + index * 8, true);
        const length = view().getUint32(vectors + index * 8 + 4, true);
        printed = (
          printed +
          new TextDecoder().decode(
            new Uint8Array(
              (memory as WebAssembly.Memory).buffer,
              pointer,
              length,
            ),
          )
        ).slice(-2_000);
        total += length;
      }
      view().setUint32(written, total, true);
      return 0;
    },
    environ_sizes_get: zeroSizes,
    args_sizes_get: zeroSizes,
    environ_get: () => 0,
    args_get: () => 0,
    sched_yield: () => 0,
    fd_close: () => EBADF,
    fd_seek: () => EBADF,
    fd_fdstat_get: () => EBADF,
    fd_prestat_get: () => EBADF,
    fd_prestat_dir_name: () => EBADF,
    proc_exit: (code: number) => {
      throw new Error(`leaf compiler exited with code ${code}`);
    },
  };
  const imports: Record<string, Record<string, WebAssembly.ImportValue>> = {};
  for (const wanted of WebAssembly.Module.imports(module)) {
    if (
      wanted.module !== "wasi_snapshot_preview1" ||
      wanted.kind !== "function"
    )
      throw new Error(
        `leaf compiler module has an unexpected import ${wanted.module}.${wanted.name}`,
      );
    (imports[wanted.module] ??= {})[wanted.name] =
      wasi[wanted.name] ?? (() => ENOSYS);
  }

  const { exports } = await WebAssembly.instantiate(module, imports);
  const { leaves_buffer: buffer, leaves_derive: answer } = exports as {
    leaves_buffer?: () => number;
    leaves_derive?: (length: number) => number;
  };
  const linear = exports.memory;
  if (
    !(linear instanceof WebAssembly.Memory) ||
    typeof buffer !== "function" ||
    typeof answer !== "function"
  )
    throw new Error("leaf compiler module does not export its interface");
  memory = linear;
  (exports._initialize as (() => void) | undefined)?.();

  let broken = false;
  const derive = (request: string): string => {
    if (broken) throw new Error("leaf compiler failed earlier; load a new one");
    const bytes = new TextEncoder().encode(request);
    let reply: string;
    try {
      const pointer = buffer();
      new Uint8Array(linear.buffer, pointer, bytes.length).set(bytes);
      const length = answer(bytes.length);
      // Compiling may have grown the memory, so it is looked up again.
      reply = new TextDecoder().decode(
        new Uint8Array(linear.buffer, pointer, length),
      );
    } catch (error) {
      broken = true;
      throw new Error(
        `leaf compiler failed: ${printed.trim() || (error as Error).message}`,
        { cause: error },
      );
    }
    const leaf = reply.slice(3);
    if (!reply.startsWith("ok ") || !HEX_32.test(leaf))
      throw new Error(
        `leaf compiler refused the request: ${reply.replace(/^error /, "")}`,
      );
    return leaf;
  };

  const accountTapleafHash = (
    stormEyeAssetId: string,
    ownerPublicKey: string,
  ): string => {
    assertHex32(stormEyeAssetId, "Storm Eye asset ID");
    assertHex32(ownerPublicKey, "owner public key");
    return derive(
      `account ${stormEyeAssetId.toLowerCase()} ${ownerPublicKey.toLowerCase()}`,
    );
  };
  const voucherTapleafHash = (
    stormEyeAssetId: string,
    authMethod: TickAuthMethod,
  ): string => {
    assertHex32(stormEyeAssetId, "Storm Eye asset ID");
    const data = authMethod?.auth_data;
    let method: string;
    let argument: string;
    if (authMethod?.kind === "scriptPubKey-auth") {
      if (
        typeof data !== "string" ||
        data.length === 0 ||
        data.length % 2 !== 0 ||
        !/^[0-9a-f]+$/i.test(data)
      )
        throw new Error("authentication scriptPubKey must be hex");
      // The covenant commits to the script's hash, as the node computes it.
      method = "script";
      argument = bytesToHex(sha256(hexToBytes(data)));
    } else if (
      authMethod?.kind === "signature-auth" ||
      authMethod?.kind === "asset-id-auth"
    ) {
      assertHex32(data, `${authMethod.kind} auth data`);
      if (authMethod.kind === "signature-auth") {
        method = "signature";
        argument = data.toLowerCase();
      } else {
        // The node puts these bytes into the covenant as they come, while the
        // compiler reads an asset ID the way Elements prints it: reversed.
        method = "asset";
        argument = bytesToHex(hexToBytes(data).reverse());
      }
    } else throw new Error("unknown authentication method");
    return derive(
      `voucher ${stormEyeAssetId.toLowerCase()} ${method} ${argument}`,
    );
  };

  return {
    accountTapleafHash,
    voucherTapleafHash,
    accountVerification: (context) => ({
      ...context,
      accountTapleafHash: accountTapleafHash(
        context.stormEyeAssetId,
        context.ownerPublicKey,
      ),
      tickTapleafHash: voucherTapleafHash(
        context.stormEyeAssetId,
        context.authScriptPubKey === undefined
          ? { kind: "signature-auth", auth_data: context.ownerPublicKey }
          : { kind: "scriptPubKey-auth", auth_data: context.authScriptPubKey },
      ),
    }),
  };
}

async function compile(
  source: LeafCompilerSource,
): Promise<WebAssembly.Module> {
  if (source instanceof WebAssembly.Module) return source;
  let loaded: Response | BufferSource | string | URL = await source;
  if (typeof loaded === "string" || loaded instanceof URL) {
    const address = String(loaded);
    if (address.startsWith("file:")) {
      // Outside a browser the module sits on disk beside this file.
      const files = "node:fs/promises";
      const { readFile } = (await import(
        /* webpackIgnore: true */ /* @vite-ignore */ files
      )) as { readFile(path: URL): Promise<Uint8Array<ArrayBuffer>> };
      loaded = await readFile(new URL(address));
    } else loaded = await fetch(loaded);
  }
  if (loaded instanceof Response) {
    if (!loaded.ok)
      throw new Error(`leaf compiler module returned HTTP ${loaded.status}`);
    loaded = await loaded.arrayBuffer();
  }
  return WebAssembly.compile(loaded);
}

function assertHex32(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || !HEX_32.test(value))
    throw new Error(`${name} must be 32-byte hex`);
}

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
const HEX_32 = /^[0-9a-f]{64}$/i;
/** WASI errno values: a bad descriptor, and a call the host does not have. */
const EBADF = 8;
const ENOSYS = 52;
/**
 * Load the leaf compiler. Without a `source` the module shipped beside this
 * file is fetched, or read from disk when the SDK runs from one.
 */
export async function loadLeafCompiler(source = new URL("./leaves.wasm", import.meta.url)) {
    const module = await compile(source);
    let memory;
    // What the module printed last: a panic explains itself there.
    let printed = "";
    const view = () => new DataView(memory.buffer);
    const zeroSizes = (count, size) => {
        view().setUint32(count, 0, true);
        view().setUint32(size, 0, true);
        return 0;
    };
    // The compiler reads no files, arguments or environment; the standard
    // library still asks for the clock and for random hash seeds.
    const wasi = {
        random_get: (pointer, length) => {
            const bytes = new Uint8Array(memory.buffer, pointer, length);
            for (let offset = 0; offset < length; offset += 65_536)
                crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
            return 0;
        },
        clock_time_get: (_id, _precision, pointer) => {
            view().setBigUint64(pointer, BigInt(Date.now()) * 1000000n, true);
            return 0;
        },
        fd_write: (_descriptor, vectors, count, written) => {
            let total = 0;
            for (let index = 0; index < count; index++) {
                const pointer = view().getUint32(vectors + index * 8, true);
                const length = view().getUint32(vectors + index * 8 + 4, true);
                printed = (printed +
                    new TextDecoder().decode(new Uint8Array(memory.buffer, pointer, length))).slice(-2_000);
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
        proc_exit: (code) => {
            throw new Error(`leaf compiler exited with code ${code}`);
        },
    };
    const imports = {};
    for (const wanted of WebAssembly.Module.imports(module)) {
        if (wanted.module !== "wasi_snapshot_preview1" ||
            wanted.kind !== "function")
            throw new Error(`leaf compiler module has an unexpected import ${wanted.module}.${wanted.name}`);
        (imports[wanted.module] ??= {})[wanted.name] =
            wasi[wanted.name] ?? (() => ENOSYS);
    }
    const { exports } = await WebAssembly.instantiate(module, imports);
    const { leaves_buffer: buffer, leaves_derive: answer } = exports;
    const linear = exports.memory;
    if (!(linear instanceof WebAssembly.Memory) ||
        typeof buffer !== "function" ||
        typeof answer !== "function")
        throw new Error("leaf compiler module does not export its interface");
    memory = linear;
    exports._initialize?.();
    let broken = false;
    const derive = (request) => {
        if (broken)
            throw new Error("leaf compiler failed earlier; load a new one");
        const bytes = new TextEncoder().encode(request);
        let reply;
        try {
            const pointer = buffer();
            new Uint8Array(linear.buffer, pointer, bytes.length).set(bytes);
            const length = answer(bytes.length);
            // Compiling may have grown the memory, so it is looked up again.
            reply = new TextDecoder().decode(new Uint8Array(linear.buffer, pointer, length));
        }
        catch (error) {
            broken = true;
            throw new Error(`leaf compiler failed: ${printed.trim() || error.message}`, { cause: error });
        }
        const leaf = reply.slice(3);
        if (!reply.startsWith("ok ") || !HEX_32.test(leaf))
            throw new Error(`leaf compiler refused the request: ${reply.replace(/^error /, "")}`);
        return leaf;
    };
    const accountTapleafHash = (stormEyeAssetId, ownerPublicKey) => {
        assertHex32(stormEyeAssetId, "Storm Eye asset ID");
        assertHex32(ownerPublicKey, "owner public key");
        return derive(`account ${stormEyeAssetId.toLowerCase()} ${ownerPublicKey.toLowerCase()}`);
    };
    const voucherTapleafHash = (stormEyeAssetId, authMethod) => {
        assertHex32(stormEyeAssetId, "Storm Eye asset ID");
        const data = authMethod?.auth_data;
        let method;
        let argument;
        if (authMethod?.kind === "scriptPubKey-auth") {
            if (typeof data !== "string" ||
                data.length === 0 ||
                data.length % 2 !== 0 ||
                !/^[0-9a-f]+$/i.test(data))
                throw new Error("authentication scriptPubKey must be hex");
            // The covenant commits to the script's hash, as the node computes it.
            method = "script";
            argument = bytesToHex(sha256(hexToBytes(data)));
        }
        else if (authMethod?.kind === "signature-auth" ||
            authMethod?.kind === "asset-id-auth") {
            assertHex32(data, `${authMethod.kind} auth data`);
            if (authMethod.kind === "signature-auth") {
                method = "signature";
                argument = data.toLowerCase();
            }
            else {
                // The node puts these bytes into the covenant as they come, while the
                // compiler reads an asset ID the way Elements prints it: reversed.
                method = "asset";
                argument = bytesToHex(hexToBytes(data).reverse());
            }
        }
        else
            throw new Error("unknown authentication method");
        return derive(`voucher ${stormEyeAssetId.toLowerCase()} ${method} ${argument}`);
    };
    return {
        accountTapleafHash,
        voucherTapleafHash,
        accountVerification: (context) => ({
            ...context,
            accountTapleafHash: accountTapleafHash(context.stormEyeAssetId, context.ownerPublicKey),
            tickTapleafHash: voucherTapleafHash(context.stormEyeAssetId, context.authScriptPubKey === undefined
                ? { kind: "signature-auth", auth_data: context.ownerPublicKey }
                : { kind: "scriptPubKey-auth", auth_data: context.authScriptPubKey }),
        }),
    };
}
async function compile(source) {
    if (source instanceof WebAssembly.Module)
        return source;
    let loaded = await source;
    if (typeof loaded === "string" || loaded instanceof URL) {
        const address = String(loaded);
        if (address.startsWith("file:")) {
            // Outside a browser the module sits on disk beside this file.
            const files = "node:fs/promises";
            const { readFile } = (await import(
            /* webpackIgnore: true */ /* @vite-ignore */ files));
            loaded = await readFile(new URL(address));
        }
        else
            loaded = await fetch(loaded);
    }
    if (loaded instanceof Response) {
        if (!loaded.ok)
            throw new Error(`leaf compiler module returned HTTP ${loaded.status}`);
        loaded = await loaded.arrayBuffer();
    }
    return WebAssembly.compile(loaded);
}
function assertHex32(value, name) {
    if (typeof value !== "string" || !HEX_32.test(value))
        throw new Error(`${name} must be 32-byte hex`);
}

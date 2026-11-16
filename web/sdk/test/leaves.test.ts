import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";

import { deriveAccount, publicKeyFromPrivateKey } from "../src";
import { loadLeafCompiler } from "../src/leaves";

/** Built by `leaves/build.sh`; a build product the repository does not keep. */
const MODULE = new URL("../dist/leaves.wasm", import.meta.url);
const STORM_EYE = "01".repeat(32);
const OWNER = publicKeyFromPrivateKey("1f".repeat(32));
const SCRIPT = `0014${"55".repeat(20)}`;
// What the contracts crate compiles for these arguments; sdk.test.ts pins the
// same leaves, and the scripts and address derived from them.
const ACCOUNT_LEAF =
  "d1754012c445c3df09b0d1bec1d6fb3addd9678ccc11e3a2833b5bb6b73a7119";
const SIGNATURE_LEAF =
  "c94377a3c786b6aefba98ca7e7c2e6ca6a9a4d6ddbdbf20a17fbc32f846be9a4";
const SCRIPT_LEAF =
  "88367e67f5f27e1aa2e906627cc1b57777489d93c7f48554065602d275c1391a";
const CONTEXT = {
  ownerPublicKey: OWNER,
  network: "elementsregtest" as const,
  stormEyeAssetId: STORM_EYE,
  tickAssetId: "02".repeat(32),
  verifierAssetId: "04".repeat(32),
};

// Without the built module there is nothing to hold against the pinned leaves.
describe.skipIf(!existsSync(MODULE))("leaf compiler", () => {
  test("compiles the leaves the contracts crate compiles", async () => {
    const leaves = await loadLeafCompiler(MODULE);
    const signature = { kind: "signature-auth", auth_data: OWNER } as const;

    expect(leaves.accountTapleafHash(STORM_EYE, OWNER)).toBe(ACCOUNT_LEAF);
    expect(leaves.voucherTapleafHash(STORM_EYE, signature)).toBe(
      SIGNATURE_LEAF,
    );
    expect(
      leaves.voucherTapleafHash(STORM_EYE, {
        kind: "scriptPubKey-auth",
        auth_data: SCRIPT,
      }),
    ).toBe(SCRIPT_LEAF);
    // Hex is read in either case, and compiling again changes nothing.
    expect(leaves.accountTapleafHash(STORM_EYE, OWNER.toUpperCase())).toBe(
      ACCOUNT_LEAF,
    );

    // Every argument reaches the leaf.
    const others = [
      leaves.accountTapleafHash("03".repeat(32), OWNER),
      leaves.accountTapleafHash(STORM_EYE, STORM_EYE),
      leaves.voucherTapleafHash("03".repeat(32), signature),
      leaves.voucherTapleafHash(STORM_EYE, {
        kind: "signature-auth",
        auth_data: STORM_EYE,
      }),
      leaves.voucherTapleafHash(STORM_EYE, {
        kind: "asset-id-auth",
        auth_data: OWNER,
      }),
      leaves.voucherTapleafHash(STORM_EYE, {
        kind: "scriptPubKey-auth",
        auth_data: `0014${"56".repeat(20)}`,
      }),
    ];
    const all = [ACCOUNT_LEAF, SIGNATURE_LEAF, SCRIPT_LEAF, ...others];
    for (const leaf of others) expect(leaf).toMatch(/^[0-9a-f]{64}$/);
    expect(new Set(all).size).toBe(all.length);
  });

  test("compiles the voucher leaves the node issues under", async () => {
    const leaves = await loadLeafCompiler(MODULE);
    // Computed by the node's issuance code for these bytes. The node takes
    // `auth_data` as it comes and prints the Storm Eye asset ID reversed.
    const storm =
      "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    const printedStorm = storm.match(/../g)!.reverse().join("");
    const data =
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    expect(
      leaves.voucherTapleafHash(printedStorm, {
        kind: "signature-auth",
        auth_data: data,
      }),
    ).toBe("ec92a4386a1d5fd7c1e41d5ecd7de82bc3742e531342330a3fe6914a677fc90a");
    for (const auth_data of [data, data.toUpperCase()])
      expect(
        leaves.voucherTapleafHash(printedStorm, {
          kind: "asset-id-auth",
          auth_data,
        }),
      ).toBe(
        "6125864e162e258d7785f830aca4b130e144210193823cc2365e0c203ad49850",
      );
  });

  test("fills the context an Account is verified against", async () => {
    const leaves = await loadLeafCompiler(MODULE);

    const verification = leaves.accountVerification(CONTEXT);
    expect(verification).toEqual({
      ...CONTEXT,
      accountTapleafHash: ACCOUNT_LEAF,
      tickTapleafHash: SIGNATURE_LEAF,
    });
    expect(deriveAccount(verification)).toMatchObject({
      address:
        "ert1pkmmvkxqa77evn3fvqjuat2dqrf6xnwtnfau9yycpwjh6acsd9ezsmggutc",
      tick_script_pubkey:
        "5120c34ad1035500f2c8e74a71f36e22ff83cb0094b6fe950b86a709b534b4b226e5",
    });

    // A wallet script authorizes the Tick; the Account stays the owner's.
    const wallet = leaves.accountVerification({
      ...CONTEXT,
      authScriptPubKey: SCRIPT,
    });
    expect(wallet).toMatchObject({
      accountTapleafHash: ACCOUNT_LEAF,
      tickTapleafHash: SCRIPT_LEAF,
      authScriptPubKey: SCRIPT,
    });
    expect(deriveAccount(wallet).tick_script_pubkey).toBe(
      "5120f84a9ece5e4fab1c3c166a27e6695bd715058afe75074ff6c879de19495a81b7",
    );
  });

  test("loads the module from bytes, a response or a compilation", async () => {
    const bytes = readFileSync(MODULE);
    for (const source of [
      bytes,
      new Response(bytes),
      Promise.resolve(new Response(bytes)),
      await WebAssembly.compile(bytes),
      MODULE.href,
    ])
      expect(
        (await loadLeafCompiler(source)).accountTapleafHash(STORM_EYE, OWNER),
      ).toBe(ACCOUNT_LEAF);

    await expect(
      loadLeafCompiler(new Response("not found", { status: 404 })),
    ).rejects.toThrow("HTTP 404");
    await expect(loadLeafCompiler(new Uint8Array(8))).rejects.toThrow();
  });

  test("refuses arguments it cannot compile for", async () => {
    const leaves = await loadLeafCompiler(MODULE);

    for (const [stormEye, owner] of [
      ["01", OWNER],
      [STORM_EYE, "not-hex"],
      [STORM_EYE, `${OWNER}00`],
    ] as const)
      expect(() => leaves.accountTapleafHash(stormEye, owner)).toThrow(
        "32-byte hex",
      );
    for (const authMethod of [
      { kind: "signature-auth", auth_data: "01" },
      { kind: "asset-id-auth", auth_data: SCRIPT },
      { kind: "scriptPubKey-auth", auth_data: "" },
      { kind: "scriptPubKey-auth", auth_data: "xyz" },
      { kind: "password-auth", auth_data: OWNER },
    ])
      expect(() =>
        leaves.voucherTapleafHash(STORM_EYE, authMethod as never),
      ).toThrow();
    // The compiler is still usable after refusing.
    expect(leaves.accountTapleafHash(STORM_EYE, OWNER)).toBe(ACCOUNT_LEAF);
  });
});

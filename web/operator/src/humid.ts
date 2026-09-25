import * as ecc from "@bitcoinerlab/secp256k1";
import BIP32Factory from "bip32";
import { Buffer } from "buffer";
import { networks, payments, type Network } from "bitcoinjs-lib";
import type { AuthConfig, AuthNetwork, OperatorIdentity } from "./types";

const bip32 = BIP32Factory(ecc);
const METHODS = ["getWalletDescriptor", "signMessage"];
const NOTIFICATIONS = ["bip122_walletDescriptorChanged"];
const WALLET_EVENTS = [
  "accountsChanged",
  "chainChanged",
  ...NOTIFICATIONS,
  "wallet_sessionChanged",
];
const REGTEST_CHAIN_KEY = "storm-humid-regtest-chain";
const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

type HumidProvider = {
  request<T>(args: { method: string; params?: unknown }): Promise<T>;
  on?: (args: {
    event: string;
    listener: (payload: unknown) => void;
  }) => () => void;
};

export type WalletDescriptorResult = {
  accountIdentifier: string;
  chainId: string;
  descriptors: Array<{
    branchDescriptors?: Array<{
      branch: string;
      change: number;
      descriptor: string;
    }>;
    branchLayout: string;
    descriptorType: string;
    format: string;
  }>;
};

type StoredHumidIdentity = Pick<
  OperatorIdentity,
  "publicKey" | "address" | "network" | "chainId" | "accountIdentifier"
>;

declare global {
  interface Window {
    humid?: HumidProvider;
  }
}

export async function connectHumid(
  config: AuthConfig,
): Promise<OperatorIdentity> {
  const provider = await waitForHumid();
  const chainId = await resolveChain(provider, config);

  await provider.request({
    method: "wallet_createSession",
    params: {
      optionalScopes: {
        [chainId]: {
          methods: METHODS,
          notifications: NOTIFICATIONS,
        },
      },
    },
  });

  const descriptor = await invoke<WalletDescriptorResult>(
    provider,
    chainId,
    "getWalletDescriptor",
    {
      descriptorType: config.descriptor_type,
      descriptorFormat: [{ format: config.descriptor_format }],
    },
  );

  if (descriptor.chainId !== chainId) {
    throw new Error("Humid returned a descriptor for a different chain.");
  }

  const derived = deriveHumidIdentity(descriptor, config.network);
  return createIdentity(provider, {
    ...derived,
    network: config.network,
    chainId,
    accountIdentifier: descriptor.accountIdentifier,
  });
}

export function restoreHumidIdentity(
  stored: StoredHumidIdentity,
): OperatorIdentity {
  return createIdentity(undefined, stored);
}

export async function validateHumidSession(
  identity: OperatorIdentity,
): Promise<boolean> {
  try {
    const provider = await waitForHumid();
    const session = await provider.request<{
      sessionScopes: Record<string, { accounts?: string[]; methods: string[] }>;
    }>({ method: "wallet_getSession" });
    const scope = session.sessionScopes[identity.chainId];

    return Boolean(
      scope?.accounts?.includes(identity.accountIdentifier) &&
      METHODS.every((method) => scope.methods.includes(method)),
    );
  } catch {
    return false;
  }
}

export async function revokeHumidSession(): Promise<void> {
  const provider = window.humid;
  if (!provider) return;

  await provider.request({ method: "wallet_revokeSession" });
}

export function subscribeToHumidChanges(listener: () => void): () => void {
  let disposed = false;
  let unsubscribers: Array<() => void> = [];

  void waitForHumid()
    .then((provider) => {
      if (disposed) return;
      unsubscribers = WALLET_EVENTS.flatMap((event) => {
        const unsubscribe = provider.on?.({ event, listener });
        return unsubscribe ? [unsubscribe] : [];
      });
    })
    .catch(listener);

  return () => {
    disposed = true;
    unsubscribers.forEach((unsubscribe) => unsubscribe());
  };
}

function createIdentity(
  initialProvider: HumidProvider | undefined,
  metadata: StoredHumidIdentity,
): OperatorIdentity {
  return {
    ...metadata,
    async sign(message) {
      const provider = initialProvider ?? (await waitForHumid());
      const result = await invoke<{
        address: string;
        protocol: string;
        signature: string;
        signatureEncoding: string;
      }>(provider, metadata.chainId, "signMessage", {
        address: metadata.address,
        message,
        protocol: "ecdsa",
      });

      if (
        result.address !== metadata.address ||
        result.protocol !== "ecdsa" ||
        result.signatureEncoding !== "hex-recoverable-ecdsa-65" ||
        !/^[0-9a-f]{130}$/i.test(result.signature)
      ) {
        throw new Error("Humid returned an unsupported message signature.");
      }

      return result.signature.toLowerCase();
    },
  };
}

async function resolveChain(
  provider: HumidProvider,
  config: AuthConfig,
): Promise<string> {
  if (config.caip2_chain_id) return config.caip2_chain_id;

  const storedChainId = localStorage.getItem(REGTEST_CHAIN_KEY);
  if (storedChainId) return storedChainId;

  const backendUrl =
    import.meta.env.VITE_HUMID_REGTEST_BACKEND_URL ?? "http://127.0.0.1:3001";
  const result = await provider.request<{ chainId: string }>({
    method: "wallet_addChain",
    params: {
      name: "HighStorm Elements Regtest",
      settings: {
        network: "regtest",
        backend: { url: backendUrl },
      },
    },
  });
  localStorage.setItem(REGTEST_CHAIN_KEY, result.chainId);
  return result.chainId;
}

async function invoke<T>(
  provider: HumidProvider,
  scope: string,
  method: string,
  params: unknown,
): Promise<T> {
  return provider.request<T>({
    method: "wallet_invokeMethod",
    params: { scope, request: { method, params } },
  });
}

async function waitForHumid(timeoutMs = 3_000): Promise<HumidProvider> {
  const startedAt = Date.now();

  while (!window.humid && Date.now() - startedAt < timeoutMs) {
    await new Promise((resolve) => window.setTimeout(resolve, 50));
  }

  if (!window.humid) {
    throw new Error("Humid is not installed or is unavailable on this page.");
  }
  return window.humid;
}

export function deriveHumidIdentity(
  result: WalletDescriptorResult,
  network: AuthNetwork,
): Pick<OperatorIdentity, "publicKey" | "address"> {
  const entries = result.descriptors.filter(
    (entry) =>
      entry.descriptorType === "publicWalletDescriptor" &&
      entry.format === "bip380-split-branches" &&
      entry.branchLayout === "split",
  );
  if (entries.length !== 1) {
    throw new Error("Humid did not return one public split-branch descriptor.");
  }

  const external = entries[0].branchDescriptors?.filter(
    (branch) => branch.branch === "external" && branch.change === 0,
  );
  if (!external || external.length !== 1) {
    throw new Error("Humid did not return one external descriptor branch.");
  }

  const xpub = parseExternalDescriptor(external[0].descriptor, network);
  const bitcoinNetwork = bitcoinNetworkFor(network);
  let publicKey: Uint8Array;
  try {
    publicKey = bip32
      .fromBase58(xpub, bitcoinNetwork)
      .derive(0)
      .derive(0).publicKey;
  } catch {
    throw new Error("Humid returned an underivable wallet descriptor.");
  }

  const address = payments.p2wpkh({
    pubkey: publicKey,
    network: elementsNetworkFor(network),
  }).address;
  if (!address) throw new Error("Could not derive the Humid signing address.");

  return {
    publicKey: Buffer.from(publicKey).toString("hex"),
    address,
  };
}

function parseExternalDescriptor(
  descriptor: string,
  network: AuthNetwork,
): string {
  const separator = descriptor.lastIndexOf("#");
  if (
    separator < 0 ||
    descriptorChecksum(descriptor.slice(0, separator)) !==
      descriptor.slice(separator + 1)
  ) {
    throw new Error("Humid returned a descriptor with an invalid checksum.");
  }

  const expression = descriptor.slice(0, separator);
  const match =
    /^elwpkh\(\[([0-9a-f]{8})\/([^\]]+)\]([xt]pub[1-9A-HJ-NP-Za-km-z]+)\/0\/\*\)$/i.exec(
      expression,
    );
  if (!match) {
    throw new Error("Humid returned an unsupported external descriptor.");
  }

  const coinType = network === "liquidv1" ? "1776" : "1";
  const normalizedOrigin = match[2].replaceAll("'", "h").toLowerCase();
  if (normalizedOrigin !== `84h/${coinType}h/0h`) {
    throw new Error("Humid returned a descriptor for a different network.");
  }
  if ((network === "liquidv1") !== match[3].startsWith("xpub")) {
    throw new Error(
      "Humid returned a descriptor with the wrong extended-key network.",
    );
  }

  return match[3];
}

export function descriptorChecksum(descriptor: string): string {
  let checksum = 1n;
  let classes = 0n;
  let classCount = 0;

  for (const character of descriptor) {
    const position = INPUT_CHARSET.indexOf(character);
    if (position < 0) return "";
    checksum = descriptorPolymod(checksum, BigInt(position & 31));
    classes = classes * 3n + BigInt(position >> 5);
    if (++classCount === 3) {
      checksum = descriptorPolymod(checksum, classes);
      classes = 0n;
      classCount = 0;
    }
  }
  if (classCount > 0) checksum = descriptorPolymod(checksum, classes);
  for (let index = 0; index < 8; index += 1) {
    checksum = descriptorPolymod(checksum, 0n);
  }
  checksum ^= 1n;

  return Array.from(
    { length: 8 },
    (_, index) =>
      CHECKSUM_CHARSET[Number((checksum >> BigInt(5 * (7 - index))) & 31n)],
  ).join("");
}

function descriptorPolymod(checksum: bigint, value: bigint): bigint {
  const top = checksum >> 35n;
  let next = ((checksum & 0x7ffffffffn) << 5n) ^ value;
  const generators = [
    0xf5dee51989n,
    0xa9fdca3312n,
    0x1bab10e32dn,
    0x3706b1677an,
    0x644d626ffdn,
  ];
  for (let index = 0; index < generators.length; index += 1) {
    if (((top >> BigInt(index)) & 1n) !== 0n) next ^= generators[index];
  }
  return next;
}

function bitcoinNetworkFor(network: AuthNetwork): Network {
  return network === "liquidv1" ? networks.bitcoin : networks.testnet;
}

function elementsNetworkFor(network: AuthNetwork): Network {
  const bitcoinNetwork = bitcoinNetworkFor(network);
  const bech32 = {
    liquidv1: "ex",
    liquidtestnet: "tex",
    elementsregtest: "ert",
  }[network];
  return { ...bitcoinNetwork, bech32 };
}

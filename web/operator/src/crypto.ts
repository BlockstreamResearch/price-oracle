import * as ecc from "@bitcoinerlab/secp256k1";
import { Buffer } from "buffer";
import { initEccLib, networks, payments, type Network } from "bitcoinjs-lib";
import { ECPairFactory } from "ecpair";
import type { AuthNetwork, OperatorIdentity } from "./types";

const ECPair = ECPairFactory(ecc);
initEccLib(ecc);

const AUTH_NETWORKS: Record<
  AuthNetwork,
  { signing: Network; elements: Network }
> = {
  liquidv1: {
    signing: networks.bitcoin,
    elements: { ...networks.bitcoin, bech32: "ex" },
  },
  liquidtestnet: {
    signing: networks.testnet,
    elements: { ...networks.testnet, bech32: "tex" },
  },
  elementsregtest: {
    signing: networks.regtest,
    elements: { ...networks.regtest, bech32: "ert" },
  },
};

export function createOperatorIdentity(
  encodedSecret: string,
  initialNetwork?: AuthNetwork,
): OperatorIdentity {
  const normalized = encodedSecret.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error("Enter a 32-byte secret key as 64 hexadecimal characters.");
  }

  const privateKey = Uint8Array.from(Buffer.from(normalized, "hex"));
  let destroyed = false;
  let publicKeyBytes: Buffer;
  try {
    publicKeyBytes = Buffer.from(ecc.xOnlyPointFromScalar(privateKey));
  } catch {
    privateKey.fill(0);
    throw new Error("The secret key is not valid for secp256k1.");
  }

  let authNetwork: AuthNetwork | null = null;
  let address: string | null = null;
  let signingAddress: string | null = null;

  function configureNetwork(network: AuthNetwork) {
    const configured = AUTH_NETWORKS[network];
    if (!configured) {
      throw new Error(`Unsupported Elements network '${network}'.`);
    }
    const nextAddress = payments.p2tr({
      internalPubkey: publicKeyBytes,
      network: configured.elements,
    }).address;
    const nextSigningAddress = payments.p2tr({
      internalPubkey: publicKeyBytes,
      network: configured.signing,
    }).address;
    if (!nextAddress || !nextSigningAddress) {
      throw new Error("Could not derive the operator address.");
    }

    authNetwork = network;
    address = nextAddress;
    signingAddress = nextSigningAddress;
  }

  if (initialNetwork) configureNetwork(initialNetwork);

  return {
    publicKey: publicKeyBytes.toString("hex"),
    get address() {
      return address;
    },
    get network() {
      return authNetwork;
    },
    configureNetwork,
    async sign(message: string) {
      if (destroyed) {
        throw new Error("The operator session has been cleared.");
      }
      if (!authNetwork || !signingAddress) {
        throw new Error("The operator network has not been configured.");
      }
      const signer = ECPair.fromPrivateKey(Buffer.from(privateKey), {
        compressed: true,
        network: AUTH_NETWORKS[authNetwork].signing,
      });
      const { Signer } = await import("bip322-js");
      return Signer.sign(signer.toWIF(), signingAddress, message);
    },
    destroy() {
      privateKey.fill(0);
      destroyed = true;
    },
  };
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export async function createWriteMessage(
  method: string,
  path: string,
  timestamp: number,
  nonce: string,
  payload: unknown,
): Promise<string> {
  const payloadHash = await sha256Hex(canonicalJson(payload));
  return [
    "high-storm:operator-write:v1",
    method.toUpperCase(),
    path,
    timestamp,
    nonce,
    payloadHash,
  ].join("\n");
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, sortJson(child)]),
    );
  }
  return value;
}

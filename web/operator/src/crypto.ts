import * as ecc from "@bitcoinerlab/secp256k1";
import { Buffer } from "buffer";
import { networks, payments } from "bitcoinjs-lib";
import { ECPairFactory } from "ecpair";
import type { OperatorIdentity } from "./types";

const ECPair = ECPairFactory(ecc);

export function createRestoredOperatorIdentity(
  publicKey: string,
  address: string,
): OperatorIdentity {
  return {
    publicKey,
    address,
    async sign() {
      throw new Error("Re-authenticate to sign this request.");
    },
    destroy() {},
  };
}

export function createOperatorIdentity(
  encodedSecret: string,
): OperatorIdentity {
  const normalized = encodedSecret.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error("Enter a 32-byte secret key as 64 hexadecimal characters.");
  }

  const privateKey = Uint8Array.from(Buffer.from(normalized, "hex"));
  let destroyed = false;
  let keyPair;
  try {
    keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey), {
      compressed: true,
      network: networks.bitcoin,
    });
  } catch {
    privateKey.fill(0);
    throw new Error("The secret key is not valid for secp256k1.");
  }

  const publicKeyBytes = Buffer.from(keyPair.publicKey);
  const address = payments.p2wpkh({
    pubkey: publicKeyBytes,
    network: networks.bitcoin,
  }).address;
  if (!address) {
    privateKey.fill(0);
    throw new Error("Could not derive the operator address.");
  }

  return {
    publicKey: publicKeyBytes.toString("hex"),
    address,
    async sign(message: string) {
      if (destroyed) {
        throw new Error("The operator session has been cleared.");
      }
      const signer = ECPair.fromPrivateKey(Buffer.from(privateKey), {
        compressed: true,
        network: networks.bitcoin,
      });
      const { Signer } = await import("bip322-js");
      return Signer.sign(signer.toWIF(), address, message);
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

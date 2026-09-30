import { createWriteMessage } from "./crypto";
import type {
  AuthConfig,
  AuthNetwork,
  OperatorIdentity,
  OperatorSession,
} from "./types";

export const HUMID_SIGNATURE_SCHEME = "bitcoin-signed-message-ecdsa-v1";

type ApiErrorBody = { error?: string };

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export class OperatorNotAuthorizedError extends ApiError {
  readonly operatorIdentifier: string;

  constructor(operatorIdentifier: string) {
    super(
      `Operator is not authorized. Register this operator identifier in HighStorm: ${operatorIdentifier}`,
      403,
    );
    this.operatorIdentifier = operatorIdentifier;
  }
}

export async function authenticateOperator(
  identity: OperatorIdentity,
): Promise<OperatorSession> {
  let challenge: {
    message: string;
    expires_at: number;
    network: AuthNetwork;
    signature_scheme: string;
  };
  try {
    challenge = await requestJson("/operators/auth/challenge", {
      method: "POST",
      body: JSON.stringify({
        public_key: identity.publicKey,
        signature_scheme: HUMID_SIGNATURE_SCHEME,
      }),
    });
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      throw new OperatorNotAuthorizedError(identity.publicKey);
    }
    throw error;
  }
  if (
    challenge.network !== identity.network ||
    challenge.signature_scheme !== HUMID_SIGNATURE_SCHEME
  ) {
    throw new Error(
      "HighStorm returned a mismatched authentication challenge.",
    );
  }
  const signature = await identity.sign(challenge.message);
  const access = await requestJson<{ token: string; expires_at: number }>(
    "/operators/auth/token",
    {
      method: "POST",
      body: JSON.stringify({
        public_key: identity.publicKey,
        signature_scheme: HUMID_SIGNATURE_SCHEME,
        message: challenge.message,
        signature,
      }),
    },
  );
  return {
    token: access.token,
    expiresAt: access.expires_at,
    identity,
  };
}

export async function getAuthConfig(): Promise<AuthConfig> {
  const config = await requestJson<AuthConfig>("/operators/auth/config");
  if (
    !["liquidv1", "liquidtestnet", "elementsregtest"].includes(
      config.network,
    ) ||
    (config.caip2_chain_id !== null &&
      typeof config.caip2_chain_id !== "string") ||
    config.signature_scheme !== HUMID_SIGNATURE_SCHEME ||
    config.descriptor_type !== "publicWalletDescriptor" ||
    config.descriptor_format !== "bip380-split-branches" ||
    config.identity_derivation?.branch !== 0 ||
    config.identity_derivation?.index !== 0
  ) {
    throw new Error("HighStorm returned an unsupported Humid configuration.");
  }
  return config;
}

export async function authenticatedGet<T>(
  session: OperatorSession,
  path: string,
): Promise<T> {
  return requestJson<T>(path, {
    headers: { Authorization: `Bearer ${session.token}` },
  });
}

export async function signedPost<T>(
  session: OperatorSession,
  path: string,
  payload: unknown,
): Promise<T> {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const message = await createWriteMessage(
    "POST",
    path,
    timestamp,
    nonce,
    payload,
  );
  return requestJson<T>(path, {
    method: "POST",
    body: JSON.stringify({
      public_key: session.identity.publicKey,
      signature_scheme: HUMID_SIGNATURE_SCHEME,
      timestamp,
      nonce,
      signature: await session.identity.sign(message),
      payload,
    }),
  });
}

async function requestJson<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...init.headers,
      },
    });
  } catch {
    throw new ApiError("Cannot reach the configured high-storm API.", 0);
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as ApiErrorBody;
    const message =
      body.error ??
      (response.status === 502
        ? "Cannot reach the configured high-storm API."
        : `Request failed with status ${response.status}`);
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

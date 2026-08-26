import { createWriteMessage } from "./crypto";
import type { OperatorIdentity, OperatorSession } from "./types";

type ApiErrorBody = { error?: string };

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function authenticateOperator(
  identity: OperatorIdentity,
): Promise<OperatorSession> {
  const challenge = await requestJson<{ message: string; expires_at: number }>(
    "/operators/auth/challenge",
    {
      method: "POST",
      body: JSON.stringify({ public_key: identity.publicKey }),
    },
  );
  const signature = await identity.sign(challenge.message);
  const access = await requestJson<{ token: string; expires_at: number }>(
    "/operators/auth/token",
    {
      method: "POST",
      body: JSON.stringify({
        public_key: identity.publicKey,
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

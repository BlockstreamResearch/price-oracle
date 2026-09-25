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
    "high-storm:operator-write:v2",
    "bitcoin-signed-message-ecdsa-v1",
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

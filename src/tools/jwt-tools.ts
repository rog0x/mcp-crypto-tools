function base64UrlDecode(input: string): string {
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64").toString("utf-8");
}

function base64UrlEncode(input: string): string {
  return Buffer.from(input, "utf-8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

interface JWTDecodeResult {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  is_expired: boolean | null;
  expires_at: string | null;
  issued_at: string | null;
  not_before: string | null;
  time_until_expiry: string | null;
  warnings: string[];
}

export function decodeJWT(token: string): JWTDecodeResult {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error(`Invalid JWT: expected 3 parts separated by dots, got ${parts.length}`);
  }

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;

  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
  } catch {
    throw new Error("Invalid JWT: could not decode header as JSON");
  }

  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    throw new Error("Invalid JWT: could not decode payload as JSON");
  }

  const signature = parts[2];
  const warnings: string[] = [];

  // Check expiry
  let isExpired: boolean | null = null;
  let expiresAt: string | null = null;
  let timeUntilExpiry: string | null = null;

  if (typeof payload.exp === "number") {
    const expDate = new Date(payload.exp * 1000);
    expiresAt = expDate.toISOString();
    const now = Date.now();
    const diff = payload.exp * 1000 - now;
    isExpired = diff < 0;

    if (isExpired) {
      const ago = Math.abs(diff);
      timeUntilExpiry = `-${formatDuration(ago)} (expired)`;
      warnings.push("Token is expired");
    } else {
      timeUntilExpiry = formatDuration(diff);
    }
  } else {
    warnings.push("No expiration claim (exp) found");
  }

  let issuedAt: string | null = null;
  if (typeof payload.iat === "number") {
    issuedAt = new Date(payload.iat * 1000).toISOString();
  }

  let notBefore: string | null = null;
  if (typeof payload.nbf === "number") {
    const nbfDate = new Date(payload.nbf * 1000);
    notBefore = nbfDate.toISOString();
    if (nbfDate.getTime() > Date.now()) {
      warnings.push("Token is not yet valid (nbf is in the future)");
    }
  }

  if (header.alg === "none") {
    warnings.push("Token uses 'none' algorithm - unsigned and insecure");
  }

  if (signature.length === 0) {
    warnings.push("Token has an empty signature");
  }

  return {
    header,
    payload,
    signature,
    is_expired: isExpired,
    expires_at: expiresAt,
    issued_at: issuedAt,
    not_before: notBefore,
    time_until_expiry: timeUntilExpiry,
    warnings,
  };
}

export function checkJWTExpiry(token: string): {
  is_expired: boolean | null;
  expires_at: string | null;
  time_until_expiry: string | null;
  issued_at: string | null;
} {
  const decoded = decodeJWT(token);
  return {
    is_expired: decoded.is_expired,
    expires_at: decoded.expires_at,
    time_until_expiry: decoded.time_until_expiry,
    issued_at: decoded.issued_at,
  };
}

export function createUnsignedJWT(
  payload: Record<string, unknown>,
  expiresInSeconds?: number
): { token: string; header: Record<string, unknown>; payload: Record<string, unknown>; warning: string } {
  const header = { alg: "none", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);

  const fullPayload: Record<string, unknown> = {
    iat: now,
    ...payload,
  };

  if (expiresInSeconds !== undefined && expiresInSeconds > 0) {
    fullPayload.exp = now + expiresInSeconds;
  }

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(fullPayload));
  const token = `${headerB64}.${payloadB64}.`;

  return {
    token,
    header,
    payload: fullPayload,
    warning: "This is an UNSIGNED token (alg: none). For testing/development only. Never use in production authentication.",
  };
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

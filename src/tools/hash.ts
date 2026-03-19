import crypto from "node:crypto";

const SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"] as const;
type HashAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

function normalizeAlgorithm(input: string): HashAlgorithm {
  const normalized = input.toLowerCase().replace(/-/g, "").replace("sha_", "sha") as string;
  const map: Record<string, HashAlgorithm> = {
    md5: "md5",
    sha1: "sha1",
    sha256: "sha256",
    sha512: "sha512",
  };
  const result = map[normalized];
  if (!result) {
    throw new Error(
      `Unsupported algorithm: "${input}". Supported: ${SUPPORTED_ALGORITHMS.join(", ")}`
    );
  }
  return result;
}

function getCryptoName(algo: HashAlgorithm): string {
  const map: Record<HashAlgorithm, string> = {
    md5: "md5",
    sha1: "sha1",
    sha256: "sha256",
    sha512: "sha512",
  };
  return map[algo];
}

export function hashText(
  text: string,
  algorithm: string,
  encoding: "hex" | "base64" = "hex"
): { algorithm: string; hash: string; encoding: string; input_length: number } {
  const algo = normalizeAlgorithm(algorithm);
  const hash = crypto.createHash(getCryptoName(algo)).update(text, "utf-8").digest(encoding);
  return {
    algorithm: algo,
    hash,
    encoding,
    input_length: text.length,
  };
}

export function hmacText(
  text: string,
  key: string,
  algorithm: string,
  encoding: "hex" | "base64" = "hex"
): { algorithm: string; hmac: string; encoding: string; input_length: number } {
  const algo = normalizeAlgorithm(algorithm);
  const hmac = crypto.createHmac(getCryptoName(algo), key).update(text, "utf-8").digest(encoding);
  return {
    algorithm: algo,
    hmac,
    encoding,
    input_length: text.length,
  };
}

export function compareHashes(
  hash1: string,
  hash2: string
): { match: boolean; hash1: string; hash2: string } {
  const a = hash1.toLowerCase().trim();
  const b = hash2.toLowerCase().trim();
  let match: boolean;
  try {
    match = crypto.timingSafeEqual(Buffer.from(a, "utf-8"), Buffer.from(b, "utf-8"));
  } catch {
    match = false;
  }
  return { match, hash1: a, hash2: b };
}

export function hashMultiple(
  text: string,
  encoding: "hex" | "base64" = "hex"
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const algo of SUPPORTED_ALGORITHMS) {
    result[algo] = crypto.createHash(getCryptoName(algo)).update(text, "utf-8").digest(encoding);
  }
  return result;
}

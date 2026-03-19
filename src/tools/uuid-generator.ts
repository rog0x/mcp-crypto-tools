import crypto from "node:crypto";

export function generateUUIDv4(count: number = 1): { uuids: string[] } {
  const n = Math.min(Math.max(1, count), 100);
  const uuids: string[] = [];
  for (let i = 0; i < n; i++) {
    uuids.push(crypto.randomUUID());
  }
  return { uuids };
}

export function generateNanoid(
  length: number = 21,
  count: number = 1
): { ids: string[]; length: number; alphabet: string } {
  const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";
  const n = Math.min(Math.max(1, count), 100);
  const len = Math.min(Math.max(1, length), 256);
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const bytes = crypto.randomBytes(len);
    let id = "";
    for (let j = 0; j < len; j++) {
      id += alphabet[bytes[j] % alphabet.length];
    }
    ids.push(id);
  }
  return { ids, length: len, alphabet };
}

export function generateULID(count: number = 1): { ulids: string[] } {
  const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const n = Math.min(Math.max(1, count), 100);
  const ulids: string[] = [];

  for (let i = 0; i < n; i++) {
    const now = Date.now();
    let timeStr = "";
    let t = now;
    for (let j = 0; j < 10; j++) {
      timeStr = ENCODING[t % 32] + timeStr;
      t = Math.floor(t / 32);
    }
    const randomBytes = crypto.randomBytes(10);
    let randomStr = "";
    for (let j = 0; j < 16; j++) {
      const byteIdx = Math.floor((j * 10) / 16);
      const bitOffset = (j * 5) % 8;
      const val =
        ((randomBytes[byteIdx] >> bitOffset) |
          ((byteIdx + 1 < 10 ? randomBytes[byteIdx + 1] : 0) << (8 - bitOffset))) &
        0x1f;
      randomStr += ENCODING[val];
    }
    ulids.push(timeStr + randomStr);
  }
  return { ulids };
}

export function generateCUID(count: number = 1): { cuids: string[] } {
  const n = Math.min(Math.max(1, count), 100);
  const cuids: string[] = [];
  const BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz";

  function toBase36(num: number, pad: number): string {
    let result = "";
    let v = Math.abs(Math.floor(num));
    do {
      result = BASE36[v % 36] + result;
      v = Math.floor(v / 36);
    } while (v > 0);
    return result.padStart(pad, "0").slice(-pad);
  }

  for (let i = 0; i < n; i++) {
    const timestamp = toBase36(Date.now(), 8);
    const randomBlock1 = toBase36(
      parseInt(crypto.randomBytes(4).toString("hex"), 16),
      8
    );
    const randomBlock2 = toBase36(
      parseInt(crypto.randomBytes(4).toString("hex"), 16),
      8
    );
    cuids.push("c" + timestamp + randomBlock1 + randomBlock2);
  }
  return { cuids };
}

export function generateRandomString(
  length: number = 16,
  charset: string = "alphanumeric",
  count: number = 1
): { strings: string[]; length: number; charset_used: string } {
  const charsets: Record<string, string> = {
    alphanumeric: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    alpha: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    numeric: "0123456789",
    hex: "0123456789abcdef",
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
    all: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=[]{}|;:,.<>?",
  };

  const chars = charsets[charset] || charset;
  if (chars.length === 0) throw new Error("Charset must not be empty");

  const len = Math.min(Math.max(1, length), 1024);
  const n = Math.min(Math.max(1, count), 100);
  const strings: string[] = [];

  for (let i = 0; i < n; i++) {
    const bytes = crypto.randomBytes(len);
    let result = "";
    for (let j = 0; j < len; j++) {
      result += chars[bytes[j] % chars.length];
    }
    strings.push(result);
  }

  return { strings, length: len, charset_used: charset in charsets ? charset : "custom" };
}

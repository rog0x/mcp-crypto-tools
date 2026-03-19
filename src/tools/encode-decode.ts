const HTML_ENTITY_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

const HTML_ENTITY_REVERSE: Record<string, string> = {};
for (const [char, entity] of Object.entries(HTML_ENTITY_MAP)) {
  HTML_ENTITY_REVERSE[entity] = char;
}

export function base64Encode(text: string): { encoded: string; original_length: number } {
  return {
    encoded: Buffer.from(text, "utf-8").toString("base64"),
    original_length: text.length,
  };
}

export function base64Decode(encoded: string): { decoded: string; encoded_length: number } {
  return {
    decoded: Buffer.from(encoded, "base64").toString("utf-8"),
    encoded_length: encoded.length,
  };
}

export function urlEncode(text: string): { encoded: string } {
  return { encoded: encodeURIComponent(text) };
}

export function urlDecode(encoded: string): { decoded: string } {
  return { decoded: decodeURIComponent(encoded) };
}

export function htmlEntitiesEncode(text: string): { encoded: string } {
  const encoded = text.replace(/[&<>"']/g, (ch) => HTML_ENTITY_MAP[ch] || ch);
  return { encoded };
}

export function htmlEntitiesDecode(text: string): { decoded: string } {
  let decoded = text;
  for (const [entity, char] of Object.entries(HTML_ENTITY_REVERSE)) {
    decoded = decoded.split(entity).join(char);
  }
  // Handle numeric entities
  decoded = decoded.replace(/&#(\d+);/g, (_, num) => String.fromCharCode(parseInt(num, 10)));
  decoded = decoded.replace(/&#x([0-9a-fA-F]+);/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
  return { decoded };
}

export function hexEncode(text: string): { encoded: string } {
  return { encoded: Buffer.from(text, "utf-8").toString("hex") };
}

export function hexDecode(hex: string): { decoded: string } {
  const cleaned = hex.replace(/\s+/g, "").replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(cleaned) || cleaned.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  return { decoded: Buffer.from(cleaned, "hex").toString("utf-8") };
}

export function binaryEncode(text: string): { encoded: string } {
  const binary = Array.from(Buffer.from(text, "utf-8"))
    .map((b) => b.toString(2).padStart(8, "0"))
    .join(" ");
  return { encoded: binary };
}

export function binaryDecode(binary: string): { decoded: string } {
  const cleaned = binary.replace(/[^01\s]/g, "");
  const bytes = cleaned.split(/\s+/).filter(Boolean);
  for (const b of bytes) {
    if (b.length !== 8) throw new Error(`Invalid binary octet: "${b}" (must be 8 bits)`);
  }
  const buf = Buffer.from(bytes.map((b) => parseInt(b, 2)));
  return { decoded: buf.toString("utf-8") };
}

interface DetectionResult {
  input: string;
  detected_formats: string[];
  analysis: Record<string, string>;
}

export function detectEncoding(text: string): DetectionResult {
  const detected: string[] = [];
  const analysis: Record<string, string> = {};
  const trimmed = text.trim();

  // Base64 check
  if (/^[A-Za-z0-9+/]+=*$/.test(trimmed) && trimmed.length >= 4 && trimmed.length % 4 === 0) {
    detected.push("base64");
    try {
      analysis["base64_decoded"] = Buffer.from(trimmed, "base64").toString("utf-8");
    } catch {
      // not valid base64
    }
  }

  // Hex check
  if (/^(0x)?[0-9a-fA-F]+$/i.test(trimmed) && trimmed.replace(/^0x/i, "").length % 2 === 0) {
    detected.push("hex");
    try {
      analysis["hex_decoded"] = Buffer.from(trimmed.replace(/^0x/i, ""), "hex").toString("utf-8");
    } catch {
      // not valid hex
    }
  }

  // URL encoded check
  if (/%[0-9A-Fa-f]{2}/.test(trimmed)) {
    detected.push("url_encoded");
    try {
      analysis["url_decoded"] = decodeURIComponent(trimmed);
    } catch {
      // not valid url encoding
    }
  }

  // HTML entities check
  if (/&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/.test(trimmed)) {
    detected.push("html_entities");
    analysis["html_decoded"] = htmlEntitiesDecode(trimmed).decoded;
  }

  // Binary check
  if (/^[01]{8}(\s+[01]{8})*$/.test(trimmed)) {
    detected.push("binary");
    try {
      analysis["binary_decoded"] = binaryDecode(trimmed).decoded;
    } catch {
      // not valid binary
    }
  }

  // JWT check
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(trimmed)) {
    detected.push("jwt");
  }

  if (detected.length === 0) {
    detected.push("plain_text");
  }

  return { input: trimmed.substring(0, 100), detected_formats: detected, analysis };
}

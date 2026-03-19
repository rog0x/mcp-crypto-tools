#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { hashText, hmacText, compareHashes, hashMultiple } from "./tools/hash.js";
import {
  base64Encode, base64Decode,
  urlEncode, urlDecode,
  htmlEntitiesEncode, htmlEntitiesDecode,
  hexEncode, hexDecode,
  binaryEncode, binaryDecode,
  detectEncoding,
} from "./tools/encode-decode.js";
import {
  generateUUIDv4, generateNanoid, generateULID,
  generateCUID, generateRandomString,
} from "./tools/uuid-generator.js";
import { generatePassword, checkPasswordStrength } from "./tools/password-tools.js";
import { decodeJWT, checkJWTExpiry, createUnsignedJWT } from "./tools/jwt-tools.js";

const server = new Server(
  {
    name: "mcp-crypto-tools",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "hash",
      description:
        "Hash text using MD5, SHA-1, SHA-256, SHA-512, or HMAC. Can also compare two hash values or compute all hash algorithms at once.",
      inputSchema: {
        type: "object" as const,
        properties: {
          action: {
            type: "string",
            enum: ["hash", "hmac", "compare", "hash_all"],
            description: "Action to perform: hash (single algorithm), hmac (keyed hash), compare (compare two hashes), hash_all (all algorithms at once)",
          },
          text: { type: "string", description: "Text to hash (for hash, hmac, hash_all actions)" },
          algorithm: {
            type: "string",
            enum: ["md5", "sha1", "sha256", "sha512"],
            description: "Hash algorithm (for hash and hmac actions). Default: sha256",
          },
          key: { type: "string", description: "Secret key (for hmac action)" },
          hash1: { type: "string", description: "First hash (for compare action)" },
          hash2: { type: "string", description: "Second hash (for compare action)" },
          encoding: {
            type: "string",
            enum: ["hex", "base64"],
            description: "Output encoding. Default: hex",
          },
        },
        required: ["action"],
      },
    },
    {
      name: "encode_decode",
      description:
        "Encode or decode text using Base64, URL encoding, HTML entities, hex, or binary. Can also auto-detect the encoding format of input.",
      inputSchema: {
        type: "object" as const,
        properties: {
          action: {
            type: "string",
            enum: [
              "base64_encode", "base64_decode",
              "url_encode", "url_decode",
              "html_encode", "html_decode",
              "hex_encode", "hex_decode",
              "binary_encode", "binary_decode",
              "detect",
            ],
            description: "Encoding/decoding action to perform",
          },
          text: { type: "string", description: "Text to encode, decode, or detect" },
        },
        required: ["action", "text"],
      },
    },
    {
      name: "generate_id",
      description:
        "Generate unique identifiers: UUID v4, nanoid, ULID, CUID, or random strings with configurable length and charset.",
      inputSchema: {
        type: "object" as const,
        properties: {
          type: {
            type: "string",
            enum: ["uuid", "nanoid", "ulid", "cuid", "random"],
            description: "Type of ID to generate",
          },
          count: { type: "number", description: "Number of IDs to generate (max 100). Default: 1" },
          length: { type: "number", description: "Length for nanoid or random string. Default: 21 for nanoid, 16 for random" },
          charset: {
            type: "string",
            description: "Charset for random strings: alphanumeric, alpha, numeric, hex, lowercase, uppercase, symbols, all, or a custom string of characters. Default: alphanumeric",
          },
        },
        required: ["type"],
      },
    },
    {
      name: "password",
      description:
        "Generate secure passwords with configurable options, or check password strength with entropy calculation and crack time estimation.",
      inputSchema: {
        type: "object" as const,
        properties: {
          action: {
            type: "string",
            enum: ["generate", "check_strength"],
            description: "Action: generate a password or check strength of an existing one",
          },
          password: { type: "string", description: "Password to check (for check_strength action)" },
          length: { type: "number", description: "Password length (for generate). Default: 16" },
          uppercase: { type: "boolean", description: "Include uppercase letters. Default: true" },
          lowercase: { type: "boolean", description: "Include lowercase letters. Default: true" },
          digits: { type: "boolean", description: "Include digits. Default: true" },
          symbols: { type: "boolean", description: "Include symbols. Default: true" },
          exclude_ambiguous: {
            type: "boolean",
            description: "Exclude ambiguous characters (0, O, l, I, 1). Default: false",
          },
          count: { type: "number", description: "Number of passwords to generate (max 100). Default: 1" },
        },
        required: ["action"],
      },
    },
    {
      name: "jwt",
      description:
        "Decode JWT tokens to inspect header and payload, check expiry status, or create unsigned JWTs for testing purposes. Not for production authentication.",
      inputSchema: {
        type: "object" as const,
        properties: {
          action: {
            type: "string",
            enum: ["decode", "check_expiry", "create_unsigned"],
            description: "Action: decode (full decode), check_expiry (just expiry info), create_unsigned (create test token)",
          },
          token: { type: "string", description: "JWT token string (for decode and check_expiry)" },
          payload: {
            type: "object",
            description: "Payload object for creating unsigned JWT (for create_unsigned)",
          },
          expires_in_seconds: {
            type: "number",
            description: "Expiration time in seconds from now (for create_unsigned)",
          },
        },
        required: ["action"],
      },
    },
  ],
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "hash": {
        const action = args?.action as string;
        const encoding = (args?.encoding as "hex" | "base64") || "hex";

        switch (action) {
          case "hash": {
            const text = args?.text as string;
            if (!text) throw new Error("'text' is required for hash action");
            const algorithm = (args?.algorithm as string) || "sha256";
            const result = hashText(text, algorithm, encoding);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          case "hmac": {
            const text = args?.text as string;
            const key = args?.key as string;
            if (!text) throw new Error("'text' is required for hmac action");
            if (!key) throw new Error("'key' is required for hmac action");
            const algorithm = (args?.algorithm as string) || "sha256";
            const result = hmacText(text, key, algorithm, encoding);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          case "compare": {
            const h1 = args?.hash1 as string;
            const h2 = args?.hash2 as string;
            if (!h1 || !h2) throw new Error("'hash1' and 'hash2' are required for compare action");
            const result = compareHashes(h1, h2);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          case "hash_all": {
            const text = args?.text as string;
            if (!text) throw new Error("'text' is required for hash_all action");
            const result = hashMultiple(text, encoding);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          default:
            throw new Error(`Unknown hash action: ${action}`);
        }
      }

      case "encode_decode": {
        const action = args?.action as string;
        const text = args?.text as string;
        if (!text) throw new Error("'text' is required");

        let result: unknown;
        switch (action) {
          case "base64_encode": result = base64Encode(text); break;
          case "base64_decode": result = base64Decode(text); break;
          case "url_encode": result = urlEncode(text); break;
          case "url_decode": result = urlDecode(text); break;
          case "html_encode": result = htmlEntitiesEncode(text); break;
          case "html_decode": result = htmlEntitiesDecode(text); break;
          case "hex_encode": result = hexEncode(text); break;
          case "hex_decode": result = hexDecode(text); break;
          case "binary_encode": result = binaryEncode(text); break;
          case "binary_decode": result = binaryDecode(text); break;
          case "detect": result = detectEncoding(text); break;
          default: throw new Error(`Unknown encode_decode action: ${action}`);
        }
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      case "generate_id": {
        const type = args?.type as string;
        const count = (args?.count as number) || 1;

        let result: unknown;
        switch (type) {
          case "uuid": result = generateUUIDv4(count); break;
          case "nanoid": {
            const length = (args?.length as number) || 21;
            result = generateNanoid(length, count);
            break;
          }
          case "ulid": result = generateULID(count); break;
          case "cuid": result = generateCUID(count); break;
          case "random": {
            const length = (args?.length as number) || 16;
            const charset = (args?.charset as string) || "alphanumeric";
            result = generateRandomString(length, charset, count);
            break;
          }
          default: throw new Error(`Unknown ID type: ${type}`);
        }
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }

      case "password": {
        const action = args?.action as string;

        switch (action) {
          case "generate": {
            const result = generatePassword({
              length: args?.length as number | undefined,
              uppercase: args?.uppercase as boolean | undefined,
              lowercase: args?.lowercase as boolean | undefined,
              digits: args?.digits as boolean | undefined,
              symbols: args?.symbols as boolean | undefined,
              exclude_ambiguous: args?.exclude_ambiguous as boolean | undefined,
              count: args?.count as number | undefined,
            });
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          case "check_strength": {
            const password = args?.password as string;
            if (!password) throw new Error("'password' is required for check_strength action");
            const result = checkPasswordStrength(password);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          default:
            throw new Error(`Unknown password action: ${action}`);
        }
      }

      case "jwt": {
        const action = args?.action as string;

        switch (action) {
          case "decode": {
            const token = args?.token as string;
            if (!token) throw new Error("'token' is required for decode action");
            const result = decodeJWT(token);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          case "check_expiry": {
            const token = args?.token as string;
            if (!token) throw new Error("'token' is required for check_expiry action");
            const result = checkJWTExpiry(token);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          case "create_unsigned": {
            const payload = (args?.payload as Record<string, unknown>) || {};
            const expiresIn = args?.expires_in_seconds as number | undefined;
            const result = createUnsignedJWT(payload, expiresIn);
            return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
          }
          default:
            throw new Error(`Unknown jwt action: ${action}`);
        }
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${message}` }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("MCP Crypto Tools server running on stdio");
}

main().catch(console.error);

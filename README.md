
# mcp-crypto-tools

Cryptography and encoding tools for AI agents, served via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io).

## Tools

### hash

Hash text using MD5, SHA-1, SHA-256, SHA-512, or HMAC. Compare two hash values. Compute all algorithms at once.

**Actions:** `hash`, `hmac`, `compare`, `hash_all`

### encode_decode

Encode and decode text using Base64, URL encoding, HTML entities, hex, or binary. Auto-detect encoding format.

**Actions:** `base64_encode`, `base64_decode`, `url_encode`, `url_decode`, `html_encode`, `html_decode`, `hex_encode`, `hex_decode`, `binary_encode`, `binary_decode`, `detect`

### generate_id

Generate unique identifiers: UUID v4, nanoid, ULID, CUID, or random strings with configurable length and charset.

**Types:** `uuid`, `nanoid`, `ulid`, `cuid`, `random`

### password

Generate secure passwords with configurable character sets, length, and count. Check password strength with entropy calculation and crack time estimation.

**Actions:** `generate`, `check_strength`

### jwt

Decode JWT tokens to inspect header and payload, check expiry status, or create unsigned JWTs for testing.

**Actions:** `decode`, `check_expiry`, `create_unsigned`

## Setup

```bash
npm install
npm run build
```

## MCP Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "crypto-tools": {
      "command": "node",
      "args": ["D:/products/mcp-servers/mcp-crypto-tools/dist/index.js"]
    }
  }
}
```

## Dependencies

- `@modelcontextprotocol/sdk` - MCP server framework
- Node.js built-in `crypto` module - all cryptographic operations

No external crypto libraries required.

## License

MIT

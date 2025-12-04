# TinyIDP MCP Workflow Guide

This guide shows how to use TinyIDP's MCP server with Claude Code for day-to-day development tasks.

## Quick Setup

### 1. Start TinyIDP

```bash
# Start the HTTP server (optional, for web UI)
python -m tinyidp

# The MCP server is configured separately in Claude Code
```

### 2. Configure Claude Code

Add to your project's `.claude/settings.json`:

```json
{
  "mcpServers": {
    "tinyidp": {
      "command": "tinyidp-mcp",
      "env": {
        "TINYIDP_CONFIG_DIR": "./config"
      }
    }
  }
}
```

Or with readonly mode (safer for shared environments):

```json
{
  "mcpServers": {
    "tinyidp": {
      "command": "tinyidp-mcp",
      "args": ["--readonly"],
      "env": {
        "TINYIDP_CONFIG_DIR": "./config"
      }
    }
  }
}
```

### 3. Verify Connection

In Claude Code, ask:
> "List all users in tinyidp"

You should see your configured users.

---

## Example Prompts for Claude Code

Copy and paste these prompts directly into Claude Code.

### Token Generation

**Generate a token for testing:**
> "Use tinyidp to generate a token for user 'admin' and show me the decoded claims"

**Generate a token with custom expiry:**
> "Generate a token for user 'testuser' with 5 minute expiry using tinyidp"

### User Management

**Create a test user on the fly:**
> "Create a new user 'testuser' with password 'test123', roles ['USER', 'TESTER'], and identity_class 'EXTERNAL' using tinyidp"

**List users and their roles:**
> "List all tinyidp users and show their roles"

**Delete a temporary test user:**
> "Delete the user 'testuser' from tinyidp"

### Token Inspection

**Decode a token without verification:**
> "Decode this JWT token using tinyidp: eyJhbGciOiJSUzI1Ni..."

**Verify a token's signature:**
> "Verify this token is valid using tinyidp: eyJhbGciOiJSUzI1Ni..."

### Configuration

**Check current settings:**
> "Show me the current tinyidp settings including issuer and token expiry"

**Reload after manual config edit:**
> "Reload the tinyidp configuration"

**Get OIDC discovery info:**
> "Get the OIDC discovery document from tinyidp"

### OAuth Clients

**List OAuth clients:**
> "List all OAuth clients configured in tinyidp"

**Create a new client:**
> "Create a new OAuth client 'test-app' with secret 'test-secret' in tinyidp"

---

## Common Workflows

### 1. Test an API Endpoint with Authentication

```
Prompt: "Generate a token for user 'admin' with tinyidp and use it to call
         GET http://localhost:8080/api/protected with that token as Bearer auth"
```

Claude Code will:
1. Call `generate_token` to get a JWT
2. Make the HTTP request with `Authorization: Bearer <token>`
3. Show you the response

### 2. Debug Token Claims

```
Prompt: "Generate a token for user 'admin' and explain what Spring Security
         authorities it will have"
```

Claude Code will:
1. Generate the token
2. Decode it to show claims
3. Explain the `authorities` array mapping

### 3. Set Up Integration Test Users

```
Prompt: "Create these test users in tinyidp:
         - 'admin-test' with roles ADMIN, USER
         - 'user-test' with role USER
         - 'readonly-test' with role VIEWER"
```

Claude Code will create all three users with appropriate settings.

### 4. Verify Token Flow

```
Prompt: "Generate a token for 'admin', decode it to show the claims,
         then verify it's valid using tinyidp"
```

This tests the full token lifecycle.

### 5. Quick Role-Based Testing

```
Prompt: "I need to test role-based access. Create a user 'role-test' with
         roles ['ADMIN', 'SPECIAL_ACCESS'], generate a token, and show me
         what authorities it will have for Spring Security"
```

---

## Tool Reference

### Read-Only Tools (always available)

| Tool | Description | Example Prompt |
|------|-------------|----------------|
| `list_users` | List all users | "List tinyidp users" |
| `get_user` | Get user details | "Get user 'admin' from tinyidp" |
| `list_clients` | List OAuth clients | "List OAuth clients" |
| `get_client` | Get client details | "Get client 'demo-client'" |
| `decode_token` | Decode JWT | "Decode this token: ..." |
| `verify_token` | Verify JWT signature | "Verify this token: ..." |
| `get_settings` | Get IdP settings | "Show tinyidp settings" |
| `reload_config` | Reload from files | "Reload tinyidp config" |
| `get_oidc_discovery` | Get OIDC discovery | "Get OIDC discovery" |
| `get_jwks` | Get JWKS | "Get the JWKS from tinyidp" |

### Mutating Tools (disabled in `--readonly` mode)

| Tool | Description | Example Prompt |
|------|-------------|----------------|
| `create_user` | Create new user | "Create user 'test' with password 'pass'" |
| `update_user` | Update user | "Update user 'test' to add role 'ADMIN'" |
| `delete_user` | Delete user | "Delete user 'test'" |
| `create_client` | Create OAuth client | "Create client 'app' with secret 'secret'" |
| `update_client` | Update client | "Update client 'app' description" |
| `delete_client` | Delete client | "Delete client 'app'" |
| `generate_token` | Generate JWT | "Generate token for 'admin'" |
| `update_settings` | Update settings | "Set token expiry to 30 minutes" |
| `save_config` | Save to YAML | "Save tinyidp config to files" |

---

## Security Notes

### Admin Secret Protection

When `TINYIDP_MCP_ADMIN_SECRET` is set, mutating tools require the secret:

```json
{
  "mcpServers": {
    "tinyidp": {
      "command": "tinyidp-mcp",
      "env": {
        "TINYIDP_CONFIG_DIR": "./config",
        "TINYIDP_MCP_ADMIN_SECRET": "your-secret-here"
      }
    }
  }
}
```

### Readonly Mode

For shared environments or when you only need introspection:

```bash
tinyidp-mcp --readonly
# or
TINYIDP_MCP_READONLY=true tinyidp-mcp
```

This completely disables all mutating tools.

---

## Troubleshooting

### "Tool not found" Error

Ensure TinyIDP is installed and `tinyidp-mcp` is in your PATH:
```bash
pip install tinyidp
which tinyidp-mcp
```

### "User not found" Error

Check your config directory is correct:
```bash
ls $TINYIDP_CONFIG_DIR/users.yaml
```

### MCP Server Not Starting

Check logs by running manually:
```bash
TINYIDP_CONFIG_DIR=./config tinyidp-mcp
```

### Permission Denied for Mutating Tools

Either:
1. Provide `admin_secret` in tool arguments (if `TINYIDP_MCP_ADMIN_SECRET` is set)
2. Or remove `TINYIDP_MCP_ADMIN_SECRET` env var for development
3. Or check you're not running in `--readonly` mode

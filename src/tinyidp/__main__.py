"""
Entry point for running TinyIDP as a module.

Usage:
    python -m tinyidp
    python -m tinyidp --port 8080
    python -m tinyidp --config /path/to/config
    python -m tinyidp init ./my-config
"""

import argparse
import sys
import os

# Add src to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Default configuration templates
DEFAULT_USERS_YAML = """# TinyIDP Users Configuration
# Documentation: https://github.com/cdelmonte-zg/tinyidp

users:
  admin:
    password: "admin"
    email: "admin@example.org"
    identity_class: "INTERNAL"
    entitlements:
      - "ADMIN_ACCESS"
      - "USER_MANAGEMENT"
    roles:
      - "USER"
      - "ADMIN"
    tenant: "default"
    source_acl:
      - "ACL_READ"
      - "ACL_WRITE"

  testuser:
    password: "test123"
    email: "test@example.org"
    roles:
      - "USER"
    tenant: "default"

default_user: "admin"
"""

DEFAULT_SETTINGS_YAML = """# TinyIDP Settings Configuration
# Documentation: https://github.com/cdelmonte-zg/tinyidp

server:
  host: "0.0.0.0"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  audience: "my-app"
  token_expiry_minutes: 60
  clients:
    - client_id: "demo-client"
      client_secret: "demo-secret"
      description: "Default demo client"

saml:
  entity_id: "http://localhost:8000/saml"
  sso_url: "http://localhost:8000/saml/sso"
  default_acs_url: "http://localhost:8080/login/saml2/sso/tinyidp"

# Authority prefixes for JWT claims
authority_prefixes:
  roles: "ROLE_"
  identity_class: "IDENTITY_"
  entitlements: "ENT_"
"""


def init_config(config_dir: str) -> None:
    """Initialize a new configuration directory with default files."""
    import os

    # Create directory
    os.makedirs(config_dir, exist_ok=True)

    # Create users.yaml
    users_path = os.path.join(config_dir, "users.yaml")
    if os.path.exists(users_path):
        print(f"  [skip] {users_path} already exists")
    else:
        with open(users_path, "w") as f:
            f.write(DEFAULT_USERS_YAML)
        print(f"  [created] {users_path}")

    # Create settings.yaml
    settings_path = os.path.join(config_dir, "settings.yaml")
    if os.path.exists(settings_path):
        print(f"  [skip] {settings_path} already exists")
    else:
        with open(settings_path, "w") as f:
            f.write(DEFAULT_SETTINGS_YAML)
        print(f"  [created] {settings_path}")

    # Create keys directory
    keys_dir = os.path.join(config_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    print(f"  [created] {keys_dir}/ (RSA keys will be auto-generated on startup)")

    print(f"""
Configuration initialized in: {os.path.abspath(config_dir)}

To start TinyIDP with this config:
    tinyidp --config {config_dir}

Or set the environment variable:
    TINYIDP_CONFIG_DIR={config_dir} tinyidp

Default credentials:
    User: admin / admin
    Client: demo-client / demo-secret
""")


def main():
    parser = argparse.ArgumentParser(
        description="TinyIDP - Lightweight Identity Provider for testing OAuth2/OIDC and SAML integrations"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new configuration directory"
    )
    init_parser.add_argument(
        "config_dir",
        nargs="?",
        default="./config",
        help="Path to create configuration directory (default: ./config)",
    )

    # wizard subcommand
    wizard_parser = subparsers.add_parser(
        "wizard",
        help="Interactive configuration wizard"
    )
    wizard_parser.add_argument(
        "config_dir",
        nargs="?",
        default="./config",
        help="Path to create configuration directory (default: ./config)",
    )

    # Main server arguments (when no subcommand)
    parser.add_argument(
        "--host",
        default=None,
        help="Host to bind to (default: from config or 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (default: from config or 8000)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to configuration directory",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )
    parser.add_argument(
        "--profile",
        choices=["dev", "stricter-dev"],
        default="dev",
        help="Security profile: dev (default) or stricter-dev",
    )

    args = parser.parse_args()

    # Handle init command
    if args.command == "init":
        print("""
    ╔══════════════════════════════════════════╗
    ║         TinyIDP Configuration Init       ║
    ╚══════════════════════════════════════════╝
        """)
        init_config(args.config_dir)
        return

    # Handle wizard command
    if args.command == "wizard":
        from tinyidp.wizard import run_wizard
        success = run_wizard(args.config_dir)
        sys.exit(0 if success else 1)

    # Run server
    from tinyidp.app import run_app

    print("""
    ╔══════════════════════════════════════════╗
    ║              TinyIDP v1.1.1              ║
    ║   Lightweight Identity Provider          ║
    ╚══════════════════════════════════════════╝
    """)

    run_app(
        host=args.host,
        port=args.port,
        debug=args.debug,
        config_dir=args.config,
        profile=args.profile,
    )


if __name__ == "__main__":
    main()

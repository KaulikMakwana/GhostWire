#!/usr/bin/env python3
"""
GhostWire C2 Framework - Main Entry Point
==========================================

This is the primary entry point for the GhostWire Command & Control (C2) framework.
The framework provides a modular, encrypted, and cross-platform C2 solution for
red team operations and penetration testing.

Key Features:
- SSL/TLS encrypted communication between agents and server
- AES-256-GCM authenticated encryption for additional security layer
- Cross-platform Python agents (Windows, Linux, macOS)
- Interactive shell sessions and fire-and-forget command execution
- Modular post-exploitation capabilities
- Session management and agent tracking

Architecture:
- C2 Server: Listens on SSL/TLS port, manages agent sessions, provides CLI
- Agent: Python script that beacons to server, executes tasks, returns results
- Payload Generator: Creates customized agents with embedded configuration
- Modules: Extensible post-exploitation capabilities

Usage:
    python3 ghostwire.py --host 0.0.0.0 --port 443
    python3 ghostwire.py --host 192.168.1.100 --port 8443

Security Note: This framework is intended for authorized testing only.
"""
import argparse
import sys
import os
import ssl
from core.c2_server import C2Server

# Add the core directory to the Python path to ensure imports work correctly
# This allows the script to find the core modules regardless of where it's executed from
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'core'))

def main():
    """
    Main entry point for the GhostWire C2 server.
    
    This function:
    1. Parses command-line arguments for host and port configuration
    2. Manages SSL certificate generation/validation
    3. Initializes and starts the C2 server
    4. Handles graceful shutdown on errors
    
    The server will:
    - Generate SSL certificates if they don't exist
    - Bind to the specified host/port with SSL/TLS
    - Start accepting agent connections
    - Provide an interactive CLI for operator commands
    """
    # Set up command-line argument parsing with helpful descriptions
    parser = argparse.ArgumentParser(
        description="GhostWire C2 Framework - Modern, encrypted, cross-platform Command & Control.",
        epilog="Example: python3 ghostwire.py --host 0.0.0.0 --port 443"
    )
    parser.add_argument("--host", help="C2 server IP/host to bind to.", default="0.0.0.0")
    parser.add_argument("--port", type=int, help="C2 server port.", default=443)
    args = parser.parse_args()

    # Define SSL certificate and key file paths relative to the script location
    # These files are required for SSL/TLS encryption of all communications
    cert_file = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_file = os.path.join(os.path.dirname(__file__), "key.pem")

    # --- SSL Certificate Management ---
    # Check if SSL certificate and private key exist
    # If not, attempt to generate them using OpenSSL for secure communications
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print(f"[!] SSL certificate or key not found.")
        print(f"[*] Attempting to generate '{os.path.basename(cert_file)}' and '{os.path.basename(key_file)}' with OpenSSL...")
        
        # Define certificate subject with generic values for self-signed certificate
        # In production, you should use proper CA-signed certificates
        subj = "/C=US/ST=None/L=None/O=GhostWire/CN=localhost"
        openssl_cmd = (
            f'openssl req -new -x509 -days 365 -nodes -out "{cert_file}" '
            f'-keyout "{key_file}" -subj "{subj}"'
        )
        
        # Execute OpenSSL command to generate certificate and key
        # This creates a self-signed certificate valid for 365 days
        result = os.system(openssl_cmd)
        if result == 0 and os.path.exists(cert_file) and os.path.exists(key_file):
            print(f"[+] SSL certificate and key generated successfully.")
        else:
            print(f"[-] FATAL: Failed to generate SSL certificate or key.")
            print(f"    Please ensure OpenSSL is installed and in your system's PATH.")
            print(f"    Manual command: {openssl_cmd}")
            sys.exit(1)

    # Initialize and start the C2 server
    # The server will handle all agent communications and provide the operator CLI
    try:
        server = C2Server(args.host, args.port, ssl_cert=cert_file, ssl_key=key_file)
        server.run()
    except Exception as e:
        print(f"[-] A fatal error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
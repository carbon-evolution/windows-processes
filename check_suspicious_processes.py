import wmi
import os
import psutil
from tabulate import tabulate
from datetime import datetime

def get_process_details():
    """Get detailed information about running processes."""
    try:
        c = wmi.WMI()
        process_list = []

        print("\n🔍 Scanning for processes...\n")
        
        for process in c.Win32_Process():
            try:
                # Basic process information
                exe_path = process.ExecutablePath or "N/A"
                owner = process.GetOwner()
                owner_info = f"{owner[2]}\\{owner[0]}" if owner[0] else "N/A"
                
                # Get process object for additional info
                try:
                    p = psutil.Process(process.ProcessId)
                    cpu_usage = p.cpu_percent()
                    memory_usage = p.memory_info().rss / 1024 / 1024  # Convert to MB
                except:
                    cpu_usage = 0
                    memory_usage = 0

                # Determine status
                if cpu_usage > 80 or memory_usage > 1000:  # High CPU or >1GB RAM
                    status = "🔴 HIGH USAGE"
                elif exe_path.lower().startswith(r'c:\windows\temp'):
                    status = "⚠️ SUSPICIOUS"
                else:
                    status = "✅ NORMAL"

                process_list.append([
                    process.ProcessId,
                    process.Name,
                    status,
                    owner_info,
                    f"{cpu_usage:.1f}%",
                    f"{memory_usage:.1f} MB",
                    exe_path[:60] + "..." if len(exe_path) > 60 else exe_path
                ])

            except Exception as e:
                continue

        return process_list
    except Exception as e:
        print(f"Error connecting to WMI: {str(e)}")
        return []

def display_process_table():
    """Display processes in a formatted table."""
    try:
        processes = get_process_details()
        
        if not processes:
            print("No processes found! Try running as administrator.")
            return

        # Sort processes by status
        risk_order = {"🔴 HIGH USAGE": 0, "⚠️ SUSPICIOUS": 1, "✅ NORMAL": 2}
        processes.sort(key=lambda x: (risk_order.get(x[2], 3), x[0]))

        # Print summary
        high_usage = sum(1 for p in processes if p[2] == "🔴 HIGH USAGE")
        suspicious = sum(1 for p in processes if p[2] == "⚠️ SUSPICIOUS")
        normal = sum(1 for p in processes if p[2] == "✅ NORMAL")
        
        print("\n=== Process Analysis Summary ===")
        print(f"Total Processes: {len(processes)}")
        print(f"High Usage: {high_usage}")
        print(f"Suspicious: {suspicious}")
        print(f"Normal: {normal}\n")

        # Display table
        headers = [
            "PID",
            "Process Name",
            "Status",
            "Owner",
            "CPU Usage",
            "Memory Usage",
            "Executable Path"
        ]
        
        print(tabulate(
            processes,
            headers=headers,
            tablefmt="grid",
            numalign="left",
            stralign="left"
        ))
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Try running the script as administrator for full access to process information.")

def check_process_vulnerabilities(process, c):
    """Check process for various vulnerabilities."""
    vulnerabilities = []
    try:
        # Get process details using psutil
        p = psutil.Process(process.ProcessId)
        
        # Check CPU usage
        if p.cpu_percent(interval=1) > 80:
            vulnerabilities.append("High CPU usage (>80%)")
        
        # Check memory usage
        if p.memory_info().rss > 1_000_000_000:  # > 1GB
            vulnerabilities.append("High memory consumption (>1GB)")
        
        # Check for multiple instances
        similar_processes = [proc for proc in c.Win32_Process() 
                           if proc.Name == process.Name]
        if len(similar_processes) > 2:
            vulnerabilities.append("Multiple instances running")
        
        # Check for system privileges
        if process.ExecutablePath and process.ExecutablePath.lower().startswith(r'c:\windows\system32'):
            try:
                if p.is_running() and p.username().lower().endswith('system'):
                    vulnerabilities.append("Running with system privileges")
            except:
                pass
        
        # Check network connections - Updated to use net_connections()
        try:
            suspicious_ports = [80, 443, 4444, 8080, 9001]
            connections = psutil.net_connections()  # Using new method
            process_connections = [conn for conn in connections 
                                if conn.pid == process.ProcessId]
            
            if any(conn.laddr.port in suspicious_ports 
                  for conn in process_connections 
                  if conn.status == 'LISTEN'):
                vulnerabilities.append("Listening on suspicious ports")
        except:
            pass
                
    except Exception as e:
        pass
    
    return vulnerabilities

if __name__ == "__main__":
    # Check if running with admin privileges
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        print("Warning: This script may need administrator privileges to access all process information.")
    
    display_process_table()

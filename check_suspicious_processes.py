import wmi
import os
import psutil
import hashlib
import requests
from tabulate import tabulate
from datetime import datetime
import pandas as pd
import jinja2

# Define suspicious directories (e.g., Temp, AppData, etc.)
SUSPICIOUS_PATHS = [
    r"C:\Users",  # Many malware hides in user profiles
    r"C:\Windows\Temp",
    r"C:\Windows\System32\Tasks",
    r"C:\Windows\SysWOW64\Tasks",
    r"C:\ProgramData",
    r"C:\Temp"
]

def is_suspicious_path(path):
    """Check if the process is running from a suspicious location."""
    if not path:
        return False
    return any(path.lower().startswith(sp.lower()) for sp in SUSPICIOUS_PATHS)

def get_process_details():
    """Get detailed information about running processes."""
    c = wmi.WMI()
    process_list = []

    print("\n🔍 Scanning for processes and checking vulnerabilities...\n")
    
    for process in c.Win32_Process():
        try:
            # Basic process information
            exe_path = process.ExecutablePath or "N/A"
            owner = process.GetOwner()
            owner_info = f"{owner[2]}\\{owner[0]}" if owner[0] else "N/A"
            command_line = process.CommandLine or "N/A"
            
            # Get creation time
            creation_date = process.CreationDate
            if creation_date:
                creation_time = datetime.strptime(creation_date.split('.')[0], '%Y%m%d%H%M%S')
                creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')
            else:
                creation_time = "N/A"
            
            # Check for suspicious path
            is_suspicious = is_suspicious_path(exe_path)
            
            # Check for vulnerabilities
            vulnerabilities = check_process_vulnerabilities(process, c)
            
            # Determine status and risk level
            if vulnerabilities:
                status = "🔴 HIGH RISK" if len(vulnerabilities) > 2 else "🟡 MEDIUM RISK"
            elif is_suspicious:
                status = "⚠️ SUSPICIOUS"
            else:
                status = "✅ SAFE"

            process_list.append([
                process.ProcessId,
                process.Name,
                status,
                owner_info,
                creation_time,
                "\n".join(vulnerabilities) if vulnerabilities else "None detected",
                exe_path[:60] + "..." if len(exe_path) > 60 else exe_path
            ])

        except Exception as e:
            continue

    return process_list

def generate_html_report(processes, summary):
    """Generate HTML report with process analysis results."""
    # Create DataFrame with matching columns
    df = pd.DataFrame(processes, columns=[
        "PID",
        "Process Name",
        "Risk Level",
        "Owner",
        "Creation Time",
        "Vulnerabilities",
        "Executable Path"
    ])

    # HTML template
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Process Security Analysis Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: auto;
            }
            h1, h2 {
                color: #333;
            }
            .summary {
                background-color: white;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 10px;
                margin-top: 15px;
            }
            .summary-item {
                padding: 10px;
                border-radius: 5px;
                text-align: center;
            }
            .high-risk { background-color: #ffebee; }
            .medium-risk { background-color: #fff3e0; }
            .suspicious { background-color: #fff8e1; }
            .safe { background-color: #e8f5e9; }
            table {
                width: 100%;
                border-collapse: collapse;
                background-color: white;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #4CAF50;
                color: white;
            }
            tr:nth-child(even) {
                background-color: #f9f9f9;
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .timestamp {
                color: #666;
                font-size: 0.9em;
                margin-top: 20px;
            }
            .risk-high { color: #d32f2f; }
            .risk-medium { color: #f57c00; }
            .risk-suspicious { color: #ffa000; }
            .risk-safe { color: #388e3c; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Process Security Analysis Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item high-risk">
                        <h3>High Risk</h3>
                        <p>{{ summary['high_risk'] }}</p>
                    </div>
                    <div class="summary-item medium-risk">
                        <h3>Medium Risk</h3>
                        <p>{{ summary['medium_risk'] }}</p>
                    </div>
                    <div class="summary-item suspicious">
                        <h3>Suspicious</h3>
                        <p>{{ summary['suspicious'] }}</p>
                    </div>
                    <div class="summary-item safe">
                        <h3>Safe</h3>
                        <p>{{ summary['safe'] }}</p>
                    </div>
                </div>
                <p>Total Processes: {{ summary['total'] }}</p>
            </div>

            {{ table | safe }}
            
            <p class="timestamp">Report generated on: {{ timestamp }}</p>
        </div>
    </body>
    </html>
    """

    # Style the DataFrame for HTML
    def style_risk_level(val):
        if "HIGH RISK" in val:
            return 'color: #d32f2f; font-weight: bold;'
        elif "MEDIUM RISK" in val:
            return 'color: #f57c00; font-weight: bold;'
        elif "SUSPICIOUS" in val:
            return 'color: #ffa000; font-weight: bold;'
        return 'color: #388e3c; font-weight: bold;'

    styled_df = df.style.applymap(style_risk_level, subset=['Risk Level'])
    
    # Render template
    template = jinja2.Template(template)
    html = template.render(
        table=styled_df.to_html(classes='styled-table', escape=False),
        summary=summary,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    # Save to file
    report_path = "process_security_report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    
    return report_path

def display_process_table():
    """Display processes and generate HTML report."""
    try:
        processes = get_process_details()
        
        if not processes:
            print("No processes found! Try running as administrator.")
            return

        # Sort processes by risk level
        risk_order = {"🔴 HIGH RISK": 0, "🟡 MEDIUM RISK": 1, "⚠️ SUSPICIOUS": 2, "✅ SAFE": 3}
        processes.sort(key=lambda x: (risk_order.get(x[2], 4), x[0]))

        # Calculate summary
        summary = {
            'total': len(processes),
            'high_risk': sum(1 for p in processes if p[2] == "🔴 HIGH RISK"),
            'medium_risk': sum(1 for p in processes if p[2] == "🟡 MEDIUM RISK"),
            'suspicious': sum(1 for p in processes if p[2] == "⚠️ SUSPICIOUS"),
            'safe': sum(1 for p in processes if p[2] == "✅ SAFE")
        }

        # Generate HTML report
        report_path = generate_html_report(processes, summary)
        print(f"\nReport generated: {os.path.abspath(report_path)}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Try running the script as administrator for full access to process information.")

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

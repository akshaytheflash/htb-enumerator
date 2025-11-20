"""
output_handler.py - Output formatting and reporting module

Handles all display, logging, and file generation for the recon-enum tool
"""

import json
import logging
import html as html_escape
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box


class OutputHandler:
    """
    Manages all output operations for the enumeration tool
    including terminal display, file generation, and logging
    """
    
    def __init__(self, 
                 target: str, 
                 output_dir: str = "./results",
                 formats: List[str] = ["txt", "json", "html", "md"],
                 verbosity: int = 1,
                 colored: bool = True):
        """
        Initialize output handler
        
        Args:
            target: Target IP/hostname
            output_dir: Base directory for results
            formats: List of output formats ['txt', 'json', 'html', 'md']
            verbosity: 0 (quiet), 1 (normal), 2 (verbose)
            colored: Enable/disable colored terminal output
        """
        self.target = target
        self.output_dir = Path(output_dir)
        self.formats = formats
        self.verbosity = verbosity
        self.colored = colored
        
        # Initialize rich console
        self.console = Console(color_system="auto" if colored else None, width=None)
        
        # Thread safety lock
        self._lock = threading.Lock()
        
        # Store scan start time
        self.scan_start_time = datetime.now()
        
        # Initialize scan data dictionary
        self.scan_data = {
            "target": target,
            "scan_start": self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_end": None,
            "ports": [],
            "services": {},
            "vulnerabilities": [],
            "os_detection": None
        }
        
        # Create output directory structure
        self.scan_dir = self.create_output_directory()
        self.raw_outputs_path = self.scan_dir / "raw_outputs"
        self.screenshots_path = self.scan_dir / "screenshots"
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging to file and optionally to console"""
        log_file = self.scan_dir / "scan.log"
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG if self.verbosity >= 2 else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler() if self.verbosity >= 2 else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def print_banner(self) -> None:
        """Display ASCII banner with tool name and target info"""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║              RECON-ENUM - Initial Enumeration                 ║
║                    Target: {self.target:<30s}     ║
╚══════════════════════════════════════════════════════════════╝
        """
        if self.verbosity > 0:
            with self._lock:
                self.console.print(banner, style="bold cyan")
                self.console.print(f"[cyan]Output Directory:[/cyan] {self.scan_dir}\n")
            self.log_to_file(f"Scan started for target: {self.target}", "INFO")
    
    def print_stage(self, stage_name: str, stage_num: int, total_stages: int) -> None:
        """Print stage header"""
        if self.verbosity > 0:
            with self._lock:
                self.console.print(f"\n[bold magenta][Stage {stage_num}/{total_stages}] {stage_name}[/bold magenta]")
            self.log_to_file(f"Starting stage: {stage_name}", "INFO")
    
    def print_success(self, message: str) -> None:
        """Print success message with [+] prefix"""
        if self.verbosity > 0:
            with self._lock:
                self.console.print(f"[green][+][/green] {message}")
            self.log_to_file(f"SUCCESS: {message}", "INFO")
    
    def print_error(self, message: str) -> None:
        """Print error message with [-] prefix"""
        if self.verbosity > 0:
            with self._lock:
                self.console.print(f"[red][-][/red] {message}")
        self.logger.error(message)
    
    def print_info(self, message: str) -> None:
        """Print info message with [*] prefix"""
        if self.verbosity > 0:
            with self._lock:
                self.console.print(f"[blue][*][/blue] {message}")
    
    def print_warning(self, message: str) -> None:
        """Print warning message with [!] prefix"""
        if self.verbosity > 0:
            with self._lock:
                self.console.print(f"[yellow][!][/yellow] {message}")
        self.logger.warning(message)
    
    def print_port_table(self, ports: List[Dict[str, Any]]) -> None:
        """
        Display open ports in formatted table
        
        Args:
            ports: List of dicts with keys: port, state, service, version
        """
        if self.verbosity == 0 or not ports:
            # Store in scan_data even if not displaying
            if ports:
                self.scan_data["ports"].extend(ports)
            return
        
        with self._lock:
            table = Table(title="Open Ports", box=box.ROUNDED)
            table.add_column("Port", style="cyan", justify="right")
            table.add_column("State", style="green")
            table.add_column("Service", style="yellow")
            table.add_column("Version", style="white")
            
            for port_info in ports:
                table.add_row(
                    str(port_info.get("port", "N/A")),
                    port_info.get("state", "unknown"),
                    port_info.get("service", "unknown"),
                    port_info.get("version", "N/A")
                )
            
            self.console.print(table)
        
        # Store in scan_data
        self.scan_data["ports"].extend(ports)
    
    def print_findings_table(self, service: str, findings: List[Dict[str, Any]]) -> None:
        """Display enumeration findings in table format"""
        if self.verbosity == 0 or not findings:
            return
        
        with self._lock:
            table = Table(title=f"{service.upper()} Enumeration Results", box=box.SIMPLE)
            table.add_column("Type", style="cyan")
            table.add_column("Finding", style="white")
            table.add_column("Severity", style="yellow")
            
            for finding in findings:
                severity_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "white"
                }.get(finding.get("severity", "info").lower(), "white")
                
                table.add_row(
                    finding.get("type", "N/A"),
                    finding.get("detail", finding.get("finding", "N/A")),
                    f"[{severity_color}]{finding.get('severity', 'info')}[/{severity_color}]"
                )
            
            self.console.print(table)
    
    @contextmanager
    def create_progress_bar(self, total: int, description: str):
        """
        Create progress bar context manager
        
        Args:
            total: Total items to process
            description: Description text
            
        Usage:
            with output.create_progress_bar(1000, "Scanning") as progress:
                for i in range(1000):
                    progress.update(1)
        """
        if self.verbosity == 0:
            # Return dummy progress object for quiet mode
            class DummyProgress:
                def update(self, n): pass
                def __enter__(self): return self
                def __exit__(self, *args): pass
            yield DummyProgress()
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=self.console
            ) as progress:
                task = progress.add_task(description, total=total)
                
                class ProgressUpdater:
                    def update(self, n):
                        progress.update(task, advance=n)
                
                yield ProgressUpdater()
    
    def print_section_header(self, title: str) -> None:
        """Print section header with decorative panel"""
        if self.verbosity > 0:
            with self._lock:
                self.console.print(Panel(f"[bold]{title}[/bold]", style="cyan"))
    
    def create_output_directory(self) -> Path:
        """Create timestamped output directory"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = self.output_dir / f"{self.target}_{timestamp}"
        
        # Create main directory and subdirectories
        scan_dir.mkdir(parents=True, exist_ok=True)
        (scan_dir / "raw_outputs").mkdir(exist_ok=True)
        (scan_dir / "screenshots").mkdir(exist_ok=True)
        
        return scan_dir
    
    def save_all_reports(self, scan_data: Dict[str, Any]) -> None:
        """Save all enabled report formats"""
        # Update scan end time
        scan_data["scan_end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_data.update(scan_data)
        
        if "txt" in self.formats:
            self.save_text_report(self.scan_data)
        if "json" in self.formats:
            self.save_json_report(self.scan_data)
        if "html" in self.formats:
            self.save_html_report(self.scan_data)
        if "md" in self.formats:
            self.save_markdown_report(self.scan_data)
    
    def save_text_report(self, scan_data: Dict[str, Any]) -> None:
        """Generate human-readable text report"""
        report_path = self.scan_dir / "scan_report.txt"
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("RECONNAISSANCE ENUMERATION REPORT\n")
                f.write("="*70 + "\n\n")
                f.write(f"Target: {scan_data['target']}\n")
                f.write(f"Scan Start: {scan_data['scan_start']}\n")
                f.write(f"Scan End: {scan_data.get('scan_end', 'N/A')}\n\n")
                
                # Port scan results
                f.write("-"*70 + "\n")
                f.write("OPEN PORTS\n")
                f.write("-"*70 + "\n")
                for port in scan_data.get('ports', []):
                    f.write(f"  Port {port['port']:<6} {port['service']:<15} {port.get('version', 'N/A')}\n")
                
                # Service enumeration results
                f.write("\n" + "-"*70 + "\n")
                f.write("SERVICE ENUMERATION\n")
                f.write("-"*70 + "\n")
                for service, data in scan_data.get('services', {}).items():
                    f.write(f"\n[{service.upper()}]\n")
                    for key, value in data.items():
                        if key != "findings":
                            f.write(f"  {key}: {value}\n")
                
                # Vulnerabilities
                if scan_data.get('vulnerabilities'):
                    f.write("\n" + "-"*70 + "\n")
                    f.write("POTENTIAL VULNERABILITIES\n")
                    f.write("-"*70 + "\n")
                    for vuln in scan_data['vulnerabilities']:
                        f.write(f"  [{vuln['severity'].upper()}] {vuln['service']}: {vuln['issue']}\n")
            
            self.logger.info(f"Text report saved: {report_path}")
        except Exception as e:
            self.print_error(f"Failed to save text report: {str(e)}")
            self.logger.exception("Error in save_text_report")
    
    def save_json_report(self, scan_data: Dict[str, Any]) -> None:
        """Save machine-readable JSON report"""
        report_path = self.scan_dir / "scan_results.json"
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=2, ensure_ascii=False, default=str)
            
            self.logger.info(f"JSON report saved: {report_path}")
        except Exception as e:
            self.print_error(f"Failed to save JSON report: {str(e)}")
            self.logger.exception("Error in save_json_report")
    
    def save_html_report(self, scan_data: Dict[str, Any]) -> None:
        """Generate styled HTML report"""
        report_path = self.scan_dir / "report.html"
        
        try:
            html_content = self._generate_html_content(scan_data)
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved: {report_path}")
        except Exception as e:
            self.print_error(f"Failed to save HTML report: {str(e)}")
            self.logger.exception("Error in save_html_report")
    
    def _generate_html_content(self, scan_data: Dict[str, Any]) -> str:
        """Generate HTML content with dark theme CSS"""
        target = scan_data.get('target', 'N/A')
        scan_start = scan_data.get('scan_start', 'N/A')
        scan_end = scan_data.get('scan_end', 'N/A')
        
        ports = scan_data.get('ports', [])
        services = scan_data.get('services', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enumeration Report - {html_escape.escape(target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117; 
            color: #c9d1d9; 
            padding: 20px;
        }}
        
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        .header {{ 
            background: linear-gradient(135deg, #1f6feb 0%, #0969da 100%);
            padding: 30px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        
        .header h1 {{ color: white; margin-bottom: 10px; }}
        
        .header p {{ color: #f0f6fc; opacity: 0.9; }}
        
        .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .meta-item {{
            background: rgba(255,255,255,0.2);
            padding: 10px;
            border-radius: 5px;
        }}
        
        .section {{ 
            background: #161b22; 
            padding: 25px; 
            margin-bottom: 20px; 
            border-radius: 8px;
            border: 1px solid #30363d;
        }}
        
        .section h2 {{ 
            color: #58a6ff; 
            margin-bottom: 15px; 
            padding-bottom: 10px;
            border-bottom: 2px solid #21262d;
        }}
        
        .section h3 {{
            color: #58a6ff;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 15px;
        }}
        
        th, td {{ 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #21262d;
        }}
        
        th {{ 
            background: #0d1117; 
            color: #58a6ff; 
            font-weight: 600;
        }}
        
        tr:hover {{ background: #1c2128; }}
        
        .severity-critical {{ color: #ff6b6b; font-weight: bold; }}
        
        .severity-high {{ color: #ffa500; font-weight: bold; }}
        
        .severity-medium {{ color: #ffd700; }}
        
        .severity-low {{ color: #58a6ff; }}
        
        .severity-info {{ color: #7d8590; }}
        
        .tag {{ 
            display: inline-block; 
            padding: 4px 10px; 
            border-radius: 4px; 
            font-size: 0.85em;
            margin-right: 5px;
        }}
        
        .tag-open {{ background: #238636; color: white; }}
        
        .tag-closed {{ background: #da3633; color: white; }}
        
        code {{ 
            background: #0d1117; 
            padding: 2px 6px; 
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #f0f6fc;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .summary-item {{
            background: #0d1117;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #58a6ff;
        }}
        
        .summary-item h3 {{
            font-size: 2em;
            color: #58a6ff;
            margin-bottom: 5px;
        }}
        
        .summary-item p {{
            color: #7d8590;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Enumeration Report</h1>
            <p><strong>Target:</strong> {html_escape.escape(target)}</p>
            <p><strong>Scan Period:</strong> {scan_start} → {scan_end if scan_end else 'In Progress'}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>{len(ports)}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="summary-item">
                    <h3>{len(services)}</h3>
                    <p>Services Detected</p>
                </div>
                <div class="summary-item">
                    <h3>{len(vulnerabilities)}</h3>
                    <p>Findings</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔌 Open Ports</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for port in scan_data.get('ports', []):
            html_content += f"""
                    <tr>
                        <td><code>{port['port']}</code></td>
                        <td><span class="tag tag-{port['state']}">{port['state']}</span></td>
                        <td>{html_escape.escape(port['service'])}</td>
                        <td>{html_escape.escape(port.get('version', 'N/A'))}</td>
                    </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>🛠️ Service Enumeration</h2>
"""
        
        for service, data in scan_data.get('services', {}).items():
            html_content += f"<h3 style='color: #58a6ff; margin-top: 20px;'>{html_escape.escape(service.upper())}</h3>"
            html_content += "<ul style='margin-left: 20px; line-height: 1.8;'>"
            for key, value in data.items():
                if key != "findings" and key != "screenshots":
                    html_content += f"<li><strong>{html_escape.escape(str(key))}:</strong> {html_escape.escape(str(value))}</li>"
            html_content += "</ul>"
        
        html_content += """
        </div>
        
        <div class="section">
            <h2>⚠️ Findings & Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Issue</th>
                        <th>Severity</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for vuln in scan_data.get('vulnerabilities', []):
            severity = vuln.get('severity', 'info').lower()
            severity_class = f"severity-{severity}"
            
            html_content += f"""
                    <tr>
                        <td><code>{html_escape.escape(vuln.get('service', 'N/A'))}</code></td>
                        <td>{html_escape.escape(vuln.get('issue', 'N/A'))}</td>
                        <td class="{severity_class}">{severity.upper()}</td>
                        <td>{html_escape.escape(vuln.get('recommendation', 'N/A'))}</td>
                    </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        return html_content
    
    def save_markdown_report(self, scan_data: Dict[str, Any]) -> None:
        """Generate markdown report for note-taking apps"""
        report_path = self.scan_dir / "notes.md"
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(f"# Enumeration Report: {scan_data['target']}\n\n")
                f.write(f"**Scan Date:** {scan_data['scan_start']}  \n")
                f.write(f"**Duration:** {scan_data['scan_start']} → {scan_data.get('scan_end', 'In Progress')}  \n\n")
                
                # Summary
                f.write("## Executive Summary\n\n")
                f.write(f"- **Open Ports:** {len(scan_data.get('ports', []))}\n")
                f.write(f"- **Services:** {len(scan_data.get('services', {}))}\n")
                f.write(f"- **Findings:** {len(scan_data.get('vulnerabilities', []))}\n\n")
                
                # Ports
                f.write("## Port Scan Results\n\n")
                f.write("| Port | State | Service | Version |\n")
                f.write("|------|-------|---------|----------|\n")
                for port in scan_data.get('ports', []):
                    f.write(f"| {port['port']} | {port['state']} | {port['service']} | {port.get('version', 'N/A')} |\n")
                
                # Services
                f.write("\n## Service Enumeration\n\n")
                for service, data in scan_data.get('services', {}).items():
                    f.write(f"### {service.upper()}\n\n")
                    for key, value in data.items():
                        if key != "findings":
                            f.write(f"- **{key}:** `{value}`\n")
                    f.write("\n")
                
                # Vulnerabilities
                if scan_data.get('vulnerabilities'):
                    f.write("## Findings & Recommendations\n\n")
                    for vuln in scan_data['vulnerabilities']:
                        f.write(f"### [{vuln['severity'].upper()}] {vuln['service']}\n\n")
                        f.write(f"**Issue:** {vuln['issue']}  \n")
                        f.write(f"**Recommendation:** {vuln.get('recommendation', 'N/A')}  \n\n")
            
            self.logger.info(f"Markdown report saved: {report_path}")
        except Exception as e:
            self.print_error(f"Failed to save markdown report: {str(e)}")
            self.logger.exception("Error in save_markdown_report")
    
    def save_raw_output(self, tool_name: str, output: str) -> None:
        """Save raw output from external tools"""
        output_path = self.scan_dir / "raw_outputs" / f"{tool_name}_output.txt"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(output)
            
            self.logger.debug(f"Raw output saved: {output_path}")
        except Exception as e:
            self.print_error(f"Failed to save raw output: {str(e)}")
            self.logger.exception("Error in save_raw_output")
    
    def log_to_file(self, message: str, level: str = "INFO") -> None:
        """Append message to scan.log"""
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(message)
    
    def generate_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from scan data"""
        # Calculate duration
        if scan_data.get('scan_end'):
            try:
                start = datetime.strptime(scan_data['scan_start'], "%Y-%m-%d %H:%M:%S")
                end = datetime.strptime(scan_data['scan_end'], "%Y-%m-%d %H:%M:%S")
                duration = str(end - start)
            except:
                duration = "In progress"
        else:
            duration = "In progress"
        
        # Extract unique services
        services = list(set([p.get('service', 'unknown') for p in scan_data.get('ports', [])]))
        
        return {
            "total_ports": len(scan_data.get('ports', [])),
            "services_found": services,
            "vulnerabilities": scan_data.get('vulnerabilities', []),
            "scan_duration": duration,
            "key_findings": [v.get('issue') for v in scan_data.get('vulnerabilities', [])[:5]]
        }
    
    def print_final_summary(self, scan_data: Dict[str, Any]) -> None:
        """Print final summary with statistics"""
        if self.verbosity == 0:
            return
        
        summary = self.generate_summary(scan_data)
        
        with self._lock:
            self.console.print("\n")
            self.console.print(Panel.fit(
                f"""
[bold cyan]Scan Complete![/bold cyan]
[yellow]Target:[/yellow] {scan_data['target']}
[yellow]Duration:[/yellow] {summary['scan_duration']}
[yellow]Open Ports:[/yellow] {summary['total_ports']}
[yellow]Services Found:[/yellow] {', '.join(summary['services_found'][:5])}
[yellow]Vulnerabilities:[/yellow] {len(summary['vulnerabilities'])}
[green]Results saved to:[/green] {self.scan_dir}
                """,
                title="Summary",
                border_style="green"
            ))
    
    def update_scan_data(self, key: str, value: Any) -> None:
        """Update scan data during enumeration"""
        if key in self.scan_data:
            if isinstance(self.scan_data[key], list):
                if isinstance(value, list):
                    self.scan_data[key].extend(value)
                else:
                    self.scan_data[key].append(value)
            elif isinstance(self.scan_data[key], dict):
                self.scan_data[key].update(value)
            else:
                self.scan_data[key] = value
        else:
            self.scan_data[key] = value

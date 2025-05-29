import typer
import asyncio
import json
import csv
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from ..api.alienvault import AlienVaultClient

app = typer.Typer(help="ThreatPulse CLI - Real-time threat intelligence")
console = Console()

def format_datetime(dt: datetime) -> str:
    """Format datetime for display"""
    return dt.strftime("%Y-%m-%d %H:%M UTC")

async def get_threat_data(days: int = 1):
    """Fetch threat data from all sources"""
    client = AlienVaultClient()
    try:
        pulses = await client.get_pulses(days_back=days)
        indicators = await client.get_indicators()
        return pulses, indicators
    finally:
        await client.close_session()

@app.command()
def malware(
    days: int = typer.Option(1, help="Number of days to look back"),
    format: str = typer.Option("table", help="Output format (table/json/csv)")
):
    """Show recent malware campaigns"""
    with Progress() as progress:
        task = progress.add_task("Fetching malware data...", total=None)
        pulses, _ = asyncio.run(get_threat_data(days))
        progress.update(task, completed=True)
    
    # Filter for malware-related pulses
    malware_pulses = [p for p in pulses if any(
        tag.lower() in ['malware', 'ransomware', 'trojan', 'botnet']
        for tag in p['tags']
    )]
    
    if format == "json":
        console.print_json(json.dumps(malware_pulses, default=str))
    elif format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=['name', 'description', 'created', 'source'])
        writer.writeheader()
        for pulse in malware_pulses:
            writer.writerow({
                'name': pulse['name'],
                'description': pulse['description'],
                'created': format_datetime(pulse['created']),
                'source': pulse['source']
            })
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Description")
        table.add_column("Created", style="dim")
        table.add_column("Source", style="dim")
        
        for pulse in malware_pulses:
            table.add_row(
                pulse['name'],
                pulse['description'][:100] + "..." if pulse['description'] else "",
                format_datetime(pulse['created']),
                pulse['source']
            )
        
        console.print(table)

@app.command()
def ips(
    days: int = typer.Option(1, help="Number of days to look back"),
    format: str = typer.Option("table", help="Output format (table/json/csv)")
):
    """List malicious IPs"""
    with Progress() as progress:
        task = progress.add_task("Fetching IP data...", total=None)
        _, indicators = asyncio.run(get_threat_data(days))
        progress.update(task, completed=True)
    
    # Filter for IP indicators
    ip_indicators = [i for i in indicators if i['type'] in ['IPv4', 'IPv6']]
    
    if format == "json":
        console.print_json(json.dumps(ip_indicators, default=str))
    elif format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=['type', 'value', 'description', 'created'])
        writer.writeheader()
        for indicator in ip_indicators:
            writer.writerow({
                'type': indicator['type'],
                'value': indicator['value'],
                'description': indicator['description'],
                'created': format_datetime(indicator['created'])
            })
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Type")
        table.add_column("IP Address")
        table.add_column("Description")
        table.add_column("First Seen", style="dim")
        
        for indicator in ip_indicators:
            table.add_row(
                indicator['type'],
                indicator['value'],
                indicator['description'][:100] + "..." if indicator['description'] else "",
                format_datetime(indicator['created'])
            )
        
        console.print(table)

if __name__ == "__main__":
    app() 
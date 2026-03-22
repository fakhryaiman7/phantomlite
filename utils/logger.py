"""
PhantomLite Logger Module
Provides colored console logging and file output using Rich.
"""
import sys
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import logging

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red bold",
    "success": "green bold",
    "debug": "dim",
    "critical": "red bold underline",
    "target": "magenta",
    "scan": "blue",
    "vuln": "red",
    "high": "red bold",
    "medium": "yellow",
    "low": "blue",
})

console = Console(theme=custom_theme)

class PhantomLogger:
    def __init__(self, name: str = "PhantomLite", log_file: str = None):
        self.name = name
        self.log_file = log_file
        self.results = []
        
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = RichHandler(
                console=console,
                show_time=True,
                show_path=False,
                markup=True,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)
    
    def _write_to_file(self, message: str, level: str = "INFO"):
        if self.log_file:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] [{level}] {message}\n")
    
    def info(self, message: str):
        self.logger.info(f"[cyan]{message}[/cyan]")
        self._write_to_file(message, "INFO")
    
    def success(self, message: str):
        self.logger.info(f"[green bold]+[/green bold] {message}")
        self._write_to_file(message, "SUCCESS")
    
    def warning(self, message: str):
        self.logger.warning(f"[yellow]![/yellow] {message}")
        self._write_to_file(message, "WARNING")
    
    def error(self, message: str):
        self.logger.error(f"[red bold]x[/red bold] {message}")
        self._write_to_file(message, "ERROR")
    
    def debug(self, message: str):
        self.logger.debug(f"[dim]{message}[/dim]")
        self._write_to_file(message, "DEBUG")
    
    def target(self, message: str):
        self.logger.info(f"[magenta]>>[/magenta] {message}")
    
    def scan(self, message: str):
        self.logger.info(f"[blue]>>[/blue] {message}")
    
    def vuln(self, message: str):
        self.logger.info(f"[red]**[/red] {message}")
    
    def header(self, message: str):
        console.print(Panel(f"[bold cyan]{message}[/bold cyan]", expand=False))
    
    def subheader(self, message: str):
        console.print(f"\n[bold blue]{'─' * 50}[/bold blue]")
        console.print(f"[bold blue]{message}[/bold blue]")
        console.print(f"[bold blue]{'─' * 50}[/bold blue]")
    
    def section(self, title: str):
        console.print(f"\n[bold cyan]+{'=' * 50}+[/bold cyan]")
        console.print(f"[bold cyan]| {title:^48} |[/bold cyan]")
        console.print(f"[bold cyan]+{'=' * 50}+[/bold cyan]\n")
    
    def print_table(self, title: str, columns: list, rows: list, style: str = "cyan"):
        table = Table(title=title, show_header=True, header_style=f"bold {style}")
        for col in columns:
            table.add_column(col, style=style)
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        console.print(table)
    
    def print_results_table(self, title: str, results: list, priority: str = "high"):
        color_map = {"high": "red", "medium": "yellow", "low": "blue"}
        color = color_map.get(priority, "cyan")
        
        table = Table(title=title, show_header=True, header_style=f"bold {color}")
        table.add_column("Target", style=color)
        table.add_column("Type", style="cyan")
        table.add_column("Score", style="green")
        table.add_column("Details", style="white")
        
        for r in results:
            table.add_row(
                r.get("target", ""),
                r.get("type", ""),
                str(r.get("score", 0)),
                r.get("details", "")
            )
        
        console.print(table)
    
    def add_result(self, result: dict):
        self.results.append(result)
    
    def save_json(self, filename: str):
        output = {
            "timestamp": datetime.now().isoformat(),
            "results": self.results
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)
        self.success(f"Results saved to {filename}")
    
    def create_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        )


def get_logger(name: str = "PhantomLite", log_file: str = None) -> PhantomLogger:
    return PhantomLogger(name, log_file)
